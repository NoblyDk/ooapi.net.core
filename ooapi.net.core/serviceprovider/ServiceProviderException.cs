using System;

namespace org.openoces.serviceprovider
{
    /// <summary>
    /// General checked exception thrown from the Service Provider Package when something fails
    /// </summary>
    class ServiceProviderException: Exception
    {
        public ServiceProviderException()
        { }
        public ServiceProviderException(string msg, Exception e) : base(msg, e)
        { }
        public ServiceProviderException(string msg): base(msg)
        { }
    }
}
