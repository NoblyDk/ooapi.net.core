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

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.pidservice;
using org.openoces.ooapi.utils;
using org.openoces.ooapi.validation;

namespace org.openoces.serviceprovider
{
    /// <summary>
    /// High-level set-up of the environment. This class is used for setting the
    /// CRL revocation checker, the environment that the system is used in, and
    /// the certificate used to communicate with the PID service.
    /// 
    /// The default settings are:
    /// <list type="bullet">
    /// <item>Revocation checking is done using partitioned CRLs.</item>
    /// <item>The OCES-II production environment is used.</item>
    /// </list>
    /// </summary>
    public class ServiceProviderSetup : IServiceProviderSetup
    {
        private readonly IEnvironments _environments;
        private IRevocationChecker _revocationChecker;

        public ServiceProviderSetup(IEnvironments environments, IRevocationChecker revocationChecker)
        {
            _environments = environments;
            _revocationChecker = revocationChecker;
        }
        const string ServiceStringPrefix = "pid.service.url.";
        
       
        public Task SetRevocationChecker(IRevocationChecker revocationChecker)
        {
            _revocationChecker = revocationChecker;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Gets the current checker.
        /// </summary>
        public IRevocationChecker CurrentChecker => _revocationChecker;

        /// <summary>
        /// Sets the environment to OCES-II production. This is the default.
        /// </summary>
        public async Task SetEnvironmentToOcesIIProduction()
        {
            await _environments.OcesEnvironments(new List<OcesEnvironment>()
            {
                OcesEnvironment.OcesII_DanidEnvProd
            });
        }

        //sets the environment to OCES-II pre production / test
        public async Task SetEnvironmentToOcesIIPreProd()
        {
            await _environments.OcesEnvironments(new List<OcesEnvironment>()
            {
                OcesEnvironment.OcesII_DanidEnvPreprod
            });
        }
    }
}
