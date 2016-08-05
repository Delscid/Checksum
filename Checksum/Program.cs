#region Copyright 2016 Shane Delany

// Copyright 2016 Shane Delany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//  Filename:  Program.cs
//  Modified:  06/08/2016
//  Created:   20/04/2016

#endregion

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Checksum
{
    public struct FileSignature
    {
        #region Constants and Fields

        public string Path;
        public long Size;
        public Dictionary<string, byte[]> Hashes;

        #endregion
    }

    public struct CommandLine
    {
        #region Constants and Fields

        public bool SuppressConsoleOutput;
        public bool SuppressFileOutput;
        public bool SuppressErrors;
        public string OutputPath;
        public string[] InputPaths;

        #endregion
    }

    public static class Program
    {
        #region Constants and Fields

        private const string DEFAULT_OUTPUT_FILENAME = "checksum.txt";

        private static readonly HashAlgorithm HashProviderMd5 = new MD5CryptoServiceProvider();
        private static readonly HashAlgorithm HashProviderSha1 = new SHA1CryptoServiceProvider();
        private static readonly HashAlgorithm HashProviderSha256 = new SHA256CryptoServiceProvider();
        private static readonly HashAlgorithm HashProviderSha512 = new SHA512CryptoServiceProvider();

        private static CommandLine CommandLine;

        #endregion

        #region Methods

        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                DisplayHelpText();
                return;
            }

            CommandLine = ParseCommandLineArguments(args);

            string outputPath = CommandLine.OutputPath;
            FileSignature currentSignature;

            using (var output = new StreamWriter(File.Create(outputPath ?? DEFAULT_OUTPUT_FILENAME)))
            {
                foreach (string path in CommandLine.InputPaths)
                {
                    if (IsDirectory(path))
                    {
                        // Directories are currently unsupported.
                        // In future, directories will be traversed and hashes will be produced for each file in the tree
                        DisplayError("Directories are currently unsupported.");
                        continue;
                    }

                    currentSignature = CreateFileSignature(path);

                    if (!CommandLine.SuppressFileOutput)
                        DisplaySignature(currentSignature);
                    if (!CommandLine.SuppressConsoleOutput)
                        WriteSignature(currentSignature, output);
                }
            }
        }

        /// <summary>
        /// Generates a signature for a given file path.
        /// </summary>
        /// <param name="path">The path for which to generate a signature.</param>
        /// <returns>A <see cref="Checksum.FileSignature"/> object containing the size and a set of hashes for the input path.</returns>
        private static FileSignature CreateFileSignature(string path)
        {
            var signature = new FileSignature();

            try
            {
                Stream stream = File.OpenRead(path);

                signature.Path = path;
                signature.Size = stream.Length;

                // Assumes that the stream can read AND seek.
                // Shouldn't crop up with the file stream opened successfully.
                signature.Hashes = new Dictionary<string, byte[]>
                {
                    {"MD5", CalculateFileHash(stream, HashProviderMd5)},
                    {"SHA1", CalculateFileHash(stream, HashProviderSha1)},
                    {"SHA256", CalculateFileHash(stream, HashProviderSha256)},
                    {"SHA512", CalculateFileHash(stream, HashProviderSha512)}
                };

                stream.Close();
            }
            catch (FileNotFoundException)
            {
                DisplayError($"File not found. ({path})");
            }
            catch (DirectoryNotFoundException)
            {
                DisplayError($"Directory not found. ({path})");
            }
            catch (PathTooLongException)
            {
                DisplayError($"File path exceeds maximum length. ({path})");
            }
            catch (UnauthorizedAccessException)
            {
                DisplayError($"File access permission denied. ({path})");
            }

            return signature;
        }

        /// <summary>
        /// Calculates a hash value for the data in a given stream using the given algorithm.
        /// </summary>
        /// <param name="stream">The stream containing the data to use.</param>
        /// <param name="algorithm">The hashing algorithm to use.</param>
        /// <returns>A byte array containing the hash bytes of the input stream.</returns>
        private static byte[] CalculateFileHash(Stream stream, HashAlgorithm algorithm)
        {
            byte[] hash = algorithm.ComputeHash(stream);

            // Prevents further hashing algorithms from failing due to incorrect stream position.
            stream.Seek(0, SeekOrigin.Begin);

            return hash;
        }

        private static CommandLine ParseCommandLineArguments(string[] args)
        {
            // Quick and Dirty command line parser implementation.
            // Far from fully functioning or "standard" compliant.
            // TODO: Replace with a more robust solution to command line parsing.

            var arguments = new CommandLine();

            List<string> filePaths = new List<string>();
            List<string> longArgs = new List<string>();
            var shortArgs = "";

            foreach (string argument in args)
            {
                if (argument.StartsWith("--"))
                    longArgs.Add(argument.TrimStart('-'));
                else if (argument.StartsWith("-"))
                    shortArgs += argument.TrimStart('-');
                else
                    filePaths.Add(argument);
            }

            // Arguments are hard coded for the time being.
            arguments.SuppressConsoleOutput = shortArgs.Contains("c") || longArgs.Contains("SuppressConsole", StringComparer.OrdinalIgnoreCase);
            arguments.SuppressFileOutput = shortArgs.Contains("f") || longArgs.Contains("SuppressFile", StringComparer.OrdinalIgnoreCase);
            arguments.SuppressErrors = shortArgs.Contains("e") || longArgs.Contains("SuppressErrors", StringComparer.OrdinalIgnoreCase);

            foreach (string argument in longArgs)
            {
                if (argument.StartsWith("output", StringComparison.OrdinalIgnoreCase) &&
                    argument.Contains("="))
                {
                    arguments.OutputPath = argument.Split('=')[1];
                }
            }

            arguments.InputPaths = filePaths.ToArray();

            return arguments;
        }

        /// <summary>
        /// Writes a message to <see cref="System.Console" /> and <see cref="System.Diagnostics.Debug"/>.
        /// </summary>
        /// <remarks>If console output has been supressed, the message will only be written to <see cref="System.Diagnostics.Debug"/>.</remarks>
        /// <param name="message">The message to display.</param>
        private static void DisplayError(string message)
        {
            if (!CommandLine.SuppressErrors)
                Console.Error.WriteLine(message);
            Debug.WriteLine($"--- Error: {message}");
        }

        /// <summary>
        /// Writes a formatted file signature to <see cref="System.Console"/>.
        /// </summary>
        /// <param name="signature">The file signature to display.</param>
        private static void DisplaySignature(FileSignature signature)
        {
            WriteSignature(signature, Console.Out);
        }

        private static void DisplayHelpText()
        {
        }

        /// <summary>
        /// Writes a formatted file signature to a given <see cref="System.IO.TextWriter"/>
        /// </summary>
        /// <param name="signature">The file signature to display.</param>
        /// <param name="writer">The <see cref="System.IO.TextWriter"/> to use.</param>
        private static void WriteSignature(FileSignature signature, TextWriter writer)
        {
            writer.WriteLine($"\"{signature.Path}\" ({signature.Size:n0} bytes)");

            foreach (string hash in signature.Hashes.Keys)
                writer.WriteLine($"    {hash,-10}{FormatHash(signature.Hashes[hash])}");
        }

        /// <summary>
        /// Checks if a given path is a directory.
        /// </summary>
        /// <param name="path">The path to check.</param>
        /// <returns>True if the path points to a directory, otherwise False.</returns>
        private static bool IsDirectory(string path)
        {
            return File.GetAttributes(path).HasFlag(FileAttributes.Directory);
        }

        private static string FormatHash(byte[] hash)
        {
            return BitConverter.ToString(hash).Replace('-', ' ');
        }

        #endregion
    }
}