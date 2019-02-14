using System;
using System.Collections.Generic;
using System.Text;
using ooapi.net.core.ooapi.pidservice;

namespace EnvironmentTester
{
    public class ClientConfiguration :IClientConfiguration
    {
        public string WsUrl { get; set; }
        public string PfxFile { get; set; }
        public string PfxPassword { get; set; }
        public byte[] PfxBytes { get; set; }
    }
}
