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
//  Modified:  20/04/2016
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
        public bool SuppressConsoleOutput;
        public bool SuppressFileOutput;
        public bool SuppressErrors;
        public string OutputPath;
        public string[] InputPaths;
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
                PrintHelpText();
                return;
            }

            CommandLine = ParseCommandLineArguments(args);

            // For further iterations which allow setting the output file path.
            // Until then, setting to null will bypass this path and use the default output file.
            string OutputPath = CommandLine.OutputPath;
            FileSignature CurrentSignature;

            using (StreamWriter OutputWriter = new StreamWriter(File.Create(OutputPath ?? DEFAULT_OUTPUT_FILENAME)))
            {
                foreach (string Path in CommandLine.InputPaths)
                {
                    if (IsDirectory(Path))
                    {
                        // Directories are currently unsupported.
                        // In future, directories will be traversed and hashes will be produced for each file in the tree
                        PrintError("Directories are currently unsupported.");
                        continue;
                    }

                    CurrentSignature = CreateFileSignature(Path);

                    if (!CommandLine.SuppressFileOutput)
                        PrintFileSignature(CurrentSignature);
                    if (!CommandLine.SuppressConsoleOutput)
                        WriteFileSignature(CurrentSignature, OutputWriter);
                }
            }
        }

        private static FileSignature CreateFileSignature(string path)
        {
            FileSignature Signature = new FileSignature();

            try
            {
                Stream Stream = File.OpenRead(path);

                Signature.Path = path;
                Signature.Size = Stream.Length;

                // Assumes that the stream can read AND seek.
                // Shouldn't crop up with the file stream opened successfully.
                Signature.Hashes = new Dictionary<string, byte[]>
                {
                    {"MD5", CalculateFileHash(Stream, HashProviderMd5)},
                    {"SHA1", CalculateFileHash(Stream, HashProviderSha1)},
                    {"SHA256", CalculateFileHash(Stream, HashProviderSha256)},
                    {"SHA512", CalculateFileHash(Stream, HashProviderSha512)}
                };

                Stream.Close();
            }
            catch (FileNotFoundException)
            {
                PrintError($"File not found. ({path})");
            }
            catch (DirectoryNotFoundException)
            {
                PrintError($"Directory not found. ({path})");
            }
            catch (PathTooLongException)
            {
                PrintError($"File path exceeds maximum length. ({path})");
            }
            catch (UnauthorizedAccessException)
            {
                PrintError($"File access permission denied. ({path})");
            }

            return Signature;
        }

        private static byte[] CalculateFileHash(Stream stream, HashAlgorithm algorithm)
        {
            byte[] Hash = algorithm.ComputeHash(stream);

            // Prevents further hashing algorithms from failing due to incorrect stream position.
            stream.Seek(0, SeekOrigin.Begin);

            return Hash;
        }

        private static string FormatHash(byte[] hash)
        {
            return BitConverter.ToString(hash).Replace('-', ' ');
        }

        private static CommandLine ParseCommandLineArguments(string[] args)
        {
            // Quick and Dirty command line parser implementation.
            // Far from fully functioning or "standard" compliant.
            // TODO: Replace with a more robust solution to command line parsing.

            CommandLine Arguments = new CommandLine();

            List<string> FilePaths = new List<string>();
            List<string> LongArgs = new List<string>();
            string ShortArgs = "";

            foreach (string Argument in args)
            {
                if (Argument.StartsWith("--"))
                    LongArgs.Add(Argument.TrimStart('-'));
                else if (Argument.StartsWith("-"))
                    ShortArgs += Argument.TrimStart('-');
                else
                    FilePaths.Add(Argument);
            }

            // Arguments are hard coded for the time being.
            Arguments.SuppressConsoleOutput = ShortArgs.Contains("c") || LongArgs.Contains("SuppressConsole", StringComparer.OrdinalIgnoreCase);
            Arguments.SuppressFileOutput = ShortArgs.Contains("f") || LongArgs.Contains("SuppressFile", StringComparer.OrdinalIgnoreCase);
            Arguments.SuppressErrors = ShortArgs.Contains("e") || LongArgs.Contains("SuppressErrors", StringComparer.OrdinalIgnoreCase);

            foreach (string Argument in LongArgs)
            {
                if (Argument.StartsWith("output", StringComparison.OrdinalIgnoreCase) &&
                    Argument.Contains("="))
                {
                    Arguments.OutputPath = Argument.Split('=')[1];
                }
            }

            Arguments.InputPaths = FilePaths.ToArray();

            return Arguments;
        }

        private static void PrintError(string message)
        {
            if (!CommandLine.SuppressErrors)
                Console.Error.WriteLine(message);
            Debug.WriteLine($"--- Error: {message}");
        }

        private static void PrintFileSignature(FileSignature signature)
        {
            WriteFileSignature(signature, Console.Out);
        }

        private static void PrintHelpText()
        {
        }

        private static bool IsDirectory(string path)
        {
            return File.GetAttributes(path).HasFlag(FileAttributes.Directory);
        }

        private static void WriteFileSignature(FileSignature signature, TextWriter writer)
        {
            writer.WriteLine($"\"{signature.Path}\" ({signature.Size:n0} bytes)");

            foreach (string Hash in signature.Hashes.Keys)
                writer.WriteLine($"    {Hash,-10}{FormatHash(signature.Hashes[Hash])}");
        }


        #endregion
    }
}