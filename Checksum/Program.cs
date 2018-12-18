#region Copyright 2018 Shane Delany

// Copyright 2018 Shane Delany
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
//  Modified:  18/12/2018
//  Created:   06/08/2016

#endregion

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Checksum
{
    public struct FileSignature
        : IEquatable<FileSignature>
    {
        public FileSignature(string path, long size, Dictionary<string, byte[]> hashes)
        {
            Path = path;
            Size = size;
            Hashes = hashes;
        }

        public string Path { get; }

        public long Size { get; }

        public Dictionary<string, byte[]> Hashes { get; }

        public bool Equals(FileSignature other)
        {
            return String.Equals(Path, other.Path, StringComparison.OrdinalIgnoreCase) && Size == other.Size && Hashes.Equals(other.Hashes);
        }

        public override bool Equals(object obj)
        {
            return !ReferenceEquals(null, obj) && obj is FileSignature other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = StringComparer.OrdinalIgnoreCase.GetHashCode(Path);
                hashCode = (hashCode * 397) ^ Size.GetHashCode();
                hashCode = (hashCode * 397) ^ Hashes.GetHashCode();
                return hashCode;
            }
        }
    }

    public struct CommandLine
        : IEquatable<CommandLine>
    {
        public CommandLine(bool suppressConsoleOutput, bool suppressFileOutput, bool suppressErrors, string outputPath, IEnumerable<string> inputPaths)
        {
            SuppressConsoleOutput = suppressConsoleOutput;
            SuppressFileOutput = suppressFileOutput;
            SuppressErrors = suppressErrors;
            OutputPath = outputPath;
            InputPaths = inputPaths.ToArray();
        }

        public bool SuppressConsoleOutput { get; }

        public bool SuppressFileOutput { get; }

        public bool SuppressErrors { get; }

        public string OutputPath { get; }

        public string[] InputPaths { get; }

        public bool Equals(CommandLine other)
        {
            return SuppressConsoleOutput == other.SuppressConsoleOutput && SuppressFileOutput == other.SuppressFileOutput && SuppressErrors == other.SuppressErrors && String.Equals(OutputPath, other.OutputPath) && InputPaths.Equals(other.InputPaths);
        }

        public override bool Equals(object obj)
        {
            return !ReferenceEquals(null, obj) && obj is CommandLine other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = SuppressConsoleOutput.GetHashCode();
                hashCode = (hashCode * 397) ^ SuppressFileOutput.GetHashCode();
                hashCode = (hashCode * 397) ^ SuppressErrors.GetHashCode();
                hashCode = (hashCode * 397) ^ OutputPath.GetHashCode();
                hashCode = (hashCode * 397) ^ InputPaths.GetHashCode();
                return hashCode;
            }
        }
    }

    public static class Program
    {
        private const string DefaultOutputFilename = "checksum.txt";

        private static readonly HashAlgorithm HashProviderMd5 = new MD5CryptoServiceProvider();
        private static readonly HashAlgorithm HashProviderSha1 = new SHA1CryptoServiceProvider();
        private static readonly HashAlgorithm HashProviderSha256 = new SHA256CryptoServiceProvider();
        private static readonly HashAlgorithm HashProviderSha512 = new SHA512CryptoServiceProvider();

        private static CommandLine CommandLine;

        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                DisplayHelpText();
                return;
            }

            CommandLine = ParseCommandLineArguments(args);

            string outputPath = CommandLine.OutputPath;

            using (var output = new StreamWriter(File.Create(outputPath ?? DefaultOutputFilename)))
            {
                foreach (string path in CommandLine.InputPaths)
                {
                    if (IsDirectory(path))
                    {
                        // Directories are currently unsupported.
                        // In future, directories will be traversed and signatures will be produced for each file in the tree
                        DisplayError("Directories are currently unsupported.");
                        continue;
                    }

                    FileSignature currentSignature = CreateFileSignature(path);

                    if (!CommandLine.SuppressConsoleOutput)
                    {
                        DisplaySignature(currentSignature);
                    }

                    if (!CommandLine.SuppressFileOutput)
                    {
                        WriteSignature(currentSignature, output);
                    }
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
            FileSignature signature = default(FileSignature);

            try
            {
                byte[] contents = File.ReadAllBytes(path);

                signature = new FileSignature(path, contents.Length, new Dictionary<string, byte[]>
                {
                    {"MD5", CalculateFileHash(contents, HashProviderMd5)},
                    {"SHA1", CalculateFileHash(contents, HashProviderSha1)},
                    {"SHA256", CalculateFileHash(contents, HashProviderSha256)},
                    {"SHA512", CalculateFileHash(contents, HashProviderSha512)}
                });
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
        /// <param name="data">The data to hash.</param>
        /// <param name="algorithm">The hashing algorithm to use.</param>
        /// <returns>A byte array containing the hash bytes of the input stream.</returns>
        private static byte[] CalculateFileHash(byte[] data, HashAlgorithm algorithm) => algorithm.ComputeHash(data);

        private static CommandLine ParseCommandLineArguments(string[] args)
        {
            // Quick and Dirty command line parser implementation.
            // Far from fully functioning or "standard compliant".
            // TODO: Replace with a more robust solution to command line parsing.

            List<string> filePaths = new List<string>();
            List<string> longArgs = new List<string>();
            StringBuilder shortArgs = new StringBuilder();
            string outPath = "";

            foreach (string argument in args)
            {
                if (argument.StartsWith("--"))
                {
                    longArgs.Add(argument.TrimStart('-'));
                }
                else if (argument.StartsWith("-"))
                {
                    shortArgs.Append(argument.TrimStart('-'));
                }
                else
                {
                    filePaths.Add(argument);
                }
            }

            // Arguments are hard coded for the time being.
            bool suppressConsoleOutput = shortArgs.ToString().Contains("c") || longArgs.Contains("SuppressConsole", StringComparer.OrdinalIgnoreCase);
            bool suppressFileOutput = shortArgs.ToString().Contains("f") || longArgs.Contains("SuppressFile", StringComparer.OrdinalIgnoreCase);
            bool suppressErrors = shortArgs.ToString().Contains("e") || longArgs.Contains("SuppressErrors", StringComparer.OrdinalIgnoreCase);

            foreach (string argument in longArgs)
            {
                if (argument.StartsWith("output", StringComparison.OrdinalIgnoreCase) && argument.Contains("="))
                {
                    outPath = argument.Split('=')[1];
                }
            }

            return new CommandLine(suppressConsoleOutput, suppressFileOutput, suppressErrors, outPath, filePaths.ToArray());
        }

        /// <summary>
        /// Writes a message to <see cref="System.Console" /> and <see cref="System.Diagnostics.Debug"/>.
        /// </summary>
        /// <remarks>If console output has been suppressed, the message will only be written to <see cref="System.Diagnostics.Debug"/>.</remarks>
        /// <param name="message">The message to display.</param>
        private static void DisplayError(string message)
        {
            Debug.WriteLine($"--- Error: {message}");

            if (CommandLine.SuppressErrors)
            {
                return;
            }

            Console.Error.WriteLine(message);
            Environment.Exit(1);
        }

        /// <summary>
        /// Writes a formatted file signature to <see cref="System.Console"/>.
        /// </summary>
        /// <param name="signature">The file signature to display.</param>
        private static void DisplaySignature(FileSignature signature) => WriteSignature(signature, Console.Out);

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
            {
                writer.WriteLine($"    {hash,-10}{FormatHash(signature.Hashes[hash])}");
            }
        }

        /// <summary>
        /// Checks if a given path is a directory.
        /// </summary>
        /// <param name="path">The path to check.</param>
        /// <returns>True if the path points to a directory, otherwise False.</returns>
        private static bool IsDirectory(string path)
        {
            try
            {
                return File.GetAttributes(path).HasFlag(FileAttributes.Directory);
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string FormatHash(byte[] hash) => BitConverter.ToString(hash).Replace('-', ' ');
    }
}
