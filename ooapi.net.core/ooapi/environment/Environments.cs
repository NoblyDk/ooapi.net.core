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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace org.openoces.ooapi.environment
{
    /// <summary>
    /// Defines the supported OCESI and OCESII test and production environments
    /// </summary>
    public class Environments : IEnvironments
    {
        private readonly IRootCertificates _rootCertificates;

        public Environments(IRootCertificates rootCertificates)
        {
            _rootCertificates = rootCertificates;
        }

        public bool HasBeenSet;
        private OcesEnvironment oces_II_environment;

        public Task setOces_II_Environment(OcesEnvironment oces_2_environment)
        {
            oces_II_environment = oces_2_environment;
            return Task.CompletedTask;
        }

        public Task<OcesEnvironment> getOces_II_Environment()
        {
            return Task.FromResult(oces_II_environment);
        }
        SemaphoreSlim mutex = new SemaphoreSlim(1);

        public IEnumerable<OcesEnvironment> TheTrustedEnvironments { get; private set; } = new[] { OcesEnvironment.OcesII_DanidEnvProd };
        
        /// <summary>
        /// Sets the environments that must be supported in this execution context.
        /// The list of environments that must be supported can only be set once in a specific execution context.
        /// </summary>
        public async Task OcesEnvironments(IList<OcesEnvironment> ocesEnvironments)
        {
            await mutex.WaitAsync().ConfigureAwait(false);
            try

            {
                if (HasBeenSet)
                {
                    throw new InvalidOperationException("Environments cannot be set twice.");
                }
                if (ocesEnvironments == null)
                {
                    throw new ArgumentException("Environments cannot be null");
                }
                if (!ocesEnvironments.Any())
                {
                    // Don't know if it's smart to throw here or not, maybe just warn about 0 count!
                    throw new ArgumentException("No environments are trusted. This can cause all sorts of problems.");
                }
                foreach (var environment in ocesEnvironments)
                {
                    if (!_rootCertificates.HasCertificate(environment).GetAwaiter().GetResult())
                    {
                        throw new ArgumentException("No root certificate for environment: " + environment);
                    }
                }
                int numberOfProductionEnvironments = await CountNumberOfProductionEnvironments(ocesEnvironments);
                if (numberOfProductionEnvironments > 0 && numberOfProductionEnvironments != ocesEnvironments.Count())
                {
                    throw new ArgumentException("Production environments cannot be mixed with test environments.");
                }

                HasBeenSet = true;
                TheTrustedEnvironments = ocesEnvironments.ToList();
            }
            finally
            {
                mutex.Release();
            }
        }

        public Task<int> CountNumberOfProductionEnvironments(IEnumerable<OcesEnvironment> environments)
        {
            int numberOfProductionEnvironments = 0;
            foreach (var e in environments)
            {
                if (OcesEnvironment.OcesII_DanidEnvProd == e)
                {
                    numberOfProductionEnvironments++;
                }
            }
            return Task.FromResult(numberOfProductionEnvironments);
        }

        /// <summary>
        /// Gets list of <code>X509Certificate</code>s of the CAs that are currently trusted.
        /// </summary>
        public async Task<IEnumerable<X509Certificate2>> TrustedCertificates()
        {
            var returnList = new List<X509Certificate2>();
            var list = TheTrustedEnvironments.ToList();

            foreach (var ocesEnvironment in list)
            {
                returnList.Add(await _rootCertificates.LookupCertificate(ocesEnvironment));
            }

            return returnList;
        }

    }
}

