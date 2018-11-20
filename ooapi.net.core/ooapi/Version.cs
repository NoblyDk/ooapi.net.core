/*
    Copyright 2010 DanID

    This file is part of OpenOcesAPI.

    OpenOcesAPI is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

    OpenOcesAPI is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with OpenOcesAPI; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


    Note to developers:
    If you add code to this file, please take a minute to add an additional
    @author statement below.
*/
using System;
using System.Reflection;
using System.Threading.Tasks;

namespace org.openoces.ooapi
{
    public class Version
    {
        public static string CompleteVersion
        {
            get { return Assembly.GetExecutingAssembly().GetName().Version.ToString(); }
        }

        public static int MajorVersion
        {
            get { return Int32.Parse(VersionArray[0]); }
        }

        public static int MinorVersion
        {
            get { return Int32.Parse(VersionArray[1]); }
        }

        public static int PatchLevel
        {
            get { return Int32.Parse(VersionArray[2]); }
        }

        public static int BuildNumber
        {
            get { return Int32.Parse(VersionArray[3]); }
        }

        static string[] VersionArray
        {
            get { return Assembly.GetExecutingAssembly().GetName().Version.ToString().Split('.'); }
        }
    }
}
