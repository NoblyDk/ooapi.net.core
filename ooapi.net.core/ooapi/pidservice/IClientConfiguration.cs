using System;
using System.Collections.Generic;
using System.Text;

namespace ooapi.net.core.ooapi.pidservice
{
    public interface IClientConfiguration
    {
        string WsUrl { get; set; }
        byte[] PfxBytes { get; set; }
        string PfxFile { get; set; }
        string PfxPassword { get; set; }
    }
}
