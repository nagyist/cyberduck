//
// Copyright (c) 2023 iterate GmbH. All rights reserved.
// https://cyberduck.io/
// 
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//

using System;
using System.IO;
using System.Reflection;
using Windows.ApplicationModel;
using Windows.Storage;

namespace Ch.Cyberduck.Core
{
    public static class RuntimeInfo
    {
        private static readonly Assembly entryAssembly;
        private static readonly Assembly coreAssembly;
        private static string revision;
        private static string versionString;

        public static string CompanyName { get; }

        public static string DataFolderName { get; set; }

        public static string Location { get; }

        public static bool Packaged { get; }

        public static string ProductName { get; }

        public static string ResourcesLocation { get; }

        public static string Revision => revision ??= Version.Revision.ToString();

        public static Version Version { get; }

        public static string VersionString => versionString ??= Version.ToString(3);

        static RuntimeInfo()
        {
            entryAssembly = Assembly.GetEntryAssembly();
            coreAssembly = typeof(RuntimeInfo).Assembly;

            if (Uri.TryCreate(coreAssembly.CodeBase, UriKind.Absolute, out var codeBaseUri))
            {
                Location = Path.GetDirectoryName(Uri.UnescapeDataString(codeBaseUri.LocalPath));
            }
            else
            {
                Location = Path.GetDirectoryName(coreAssembly.Location);
            }

            if (entryAssembly?.GetName() is AssemblyName entryName)
            {
                ProductName = entryName.Name;
                Version = entryName.Version;
            }

            CompanyName = entryAssembly.GetCustomAttribute<AssemblyCompanyAttribute>() switch
            {
                AssemblyCompanyAttribute company => company.Company,
                _ => ProductName,
            };

            DataFolderName = ProductName;
            Packaged = Utils.IsRunningAsUWP;

            ResourcesLocation = Packaged
                ? Package.Current.InstalledPath
                : Location;
        }
    }
}
