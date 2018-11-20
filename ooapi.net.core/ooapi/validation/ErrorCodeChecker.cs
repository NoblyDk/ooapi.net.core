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
using System.Collections.Generic;
using System.Threading.Tasks;

namespace org.openoces.ooapi.validation
{
    public class ErrorCodeChecker : IErrorCodeChecker
    {
        private readonly List<string> ErrorCodes = new List<string> { 
			"APP001","APP002","APP003","APP004","APP007","APP008","APP009","APP010",
			"AUTH001","AUTH003","AUTH004","AUTH005","AUTH006","AUTH007","AUTH008","AUTH009","AUTH010","AUTH011","AUTH012","AUTH013","AUTH017","AUTH018","AUTH019","AUTH020",
			"CAN001","CAN002","CAN003","CAN004","CAN005","CAN006","CAN007","CAN008",
			"CAPP004",
			"LIB002",
			"LOCK001","LOCK002","LOCK003",
			"SRV001","SRV002","SRV003","SRV004","SRV005","SRV006","SRV007","SRV008","SRV010","SRV011",
			"OCES001","OCES002","OCES003","OCES004","OCES005","OCES006"};

      
        public async Task<bool> HasError(string text)
        {
            return await ExtractError(text) != null;
        }

        public Task<string> ExtractError(string text)
        {
            return Task.FromResult(ErrorCodes.Contains(text.ToUpper()) ? text.ToUpper() : null);
        }
    }
}

