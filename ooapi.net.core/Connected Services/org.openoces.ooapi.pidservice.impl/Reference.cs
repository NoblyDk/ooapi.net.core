﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     //
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace org.openoces.ooapi.pidservice.impl
{
    using System.Runtime.Serialization;
    
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    [System.Runtime.Serialization.DataContractAttribute(Name="PIDRequest", Namespace="java:dk.certifikat.pid.webservices")]
    public partial class PIDRequest : object
    {
        
        private string CPRField;
        
        private string PIDField;
        
        private string b64CertField;
        
        private string idField;
        
        private string serviceIdField;
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string CPR
        {
            get
            {
                return this.CPRField;
            }
            set
            {
                this.CPRField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string PID
        {
            get
            {
                return this.PIDField;
            }
            set
            {
                this.PIDField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string b64Cert
        {
            get
            {
                return this.b64CertField;
            }
            set
            {
                this.b64CertField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string serviceId
        {
            get
            {
                return this.serviceIdField;
            }
            set
            {
                this.serviceIdField = value;
            }
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    [System.Runtime.Serialization.DataContractAttribute(Name="PIDReply", Namespace="java:dk.certifikat.pid.webservices")]
    public partial class PIDReply : object
    {
        
        private string CPRField;
        
        private string PIDField;
        
        private string idField;
        
        private string redirURLField;
        
        private string statusCodeField;
        
        private string statusTextDKField;
        
        private string statusTextUKField;
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string CPR
        {
            get
            {
                return this.CPRField;
            }
            set
            {
                this.CPRField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string PID
        {
            get
            {
                return this.PIDField;
            }
            set
            {
                this.PIDField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string redirURL
        {
            get
            {
                return this.redirURLField;
            }
            set
            {
                this.redirURLField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string statusCode
        {
            get
            {
                return this.statusCodeField;
            }
            set
            {
                this.statusCodeField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string statusTextDK
        {
            get
            {
                return this.statusTextDKField;
            }
            set
            {
                this.statusTextDKField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public string statusTextUK
        {
            get
            {
                return this.statusTextUKField;
            }
            set
            {
                this.statusTextUKField = value;
            }
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://localhost/", ConfigurationName="org.openoces.ooapi.pidservice.impl.pidwsdocPort")]
    public interface pidwsdocPort
    {
        
        [System.ServiceModel.OperationContractAttribute(Action="", ReplyAction="*")]
        System.Threading.Tasks.Task<org.openoces.ooapi.pidservice.impl.pidResponse> pidAsync(org.openoces.ooapi.pidservice.impl.pidRequest1 request);
        
        [System.ServiceModel.OperationContractAttribute(Action="", ReplyAction="*")]
        [return: System.ServiceModel.MessageParameterAttribute(Name="result")]
        System.Threading.Tasks.Task<int> testConnectionAsync(int intVal);
        
        [System.ServiceModel.OperationContractAttribute(Action="", ReplyAction="*")]
        System.Threading.Tasks.Task testAsync();
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class pidRequest1
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="pid", Namespace="http://localhost/", Order=0)]
        public org.openoces.ooapi.pidservice.impl.pidRequest1Body Body;
        
        public pidRequest1()
        {
        }
        
        public pidRequest1(org.openoces.ooapi.pidservice.impl.pidRequest1Body Body)
        {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://localhost/")]
    public partial class pidRequest1Body
    {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public System.Collections.Generic.List<org.openoces.ooapi.pidservice.impl.PIDRequest> pIDRequests;
        
        public pidRequest1Body()
        {
        }
        
        public pidRequest1Body(System.Collections.Generic.List<org.openoces.ooapi.pidservice.impl.PIDRequest> pIDRequests)
        {
            this.pIDRequests = pIDRequests;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class pidResponse
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="pidResponse", Namespace="http://localhost/", Order=0)]
        public org.openoces.ooapi.pidservice.impl.pidResponseBody Body;
        
        public pidResponse()
        {
        }
        
        public pidResponse(org.openoces.ooapi.pidservice.impl.pidResponseBody Body)
        {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://localhost/")]
    public partial class pidResponseBody
    {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public System.Collections.Generic.List<org.openoces.ooapi.pidservice.impl.PIDReply> result;
        
        public pidResponseBody()
        {
        }
        
        public pidResponseBody(System.Collections.Generic.List<org.openoces.ooapi.pidservice.impl.PIDReply> result)
        {
            this.result = result;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    public interface pidwsdocPortChannel : org.openoces.ooapi.pidservice.impl.pidwsdocPort, System.ServiceModel.IClientChannel
    {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("dotnet-svcutil", "1.0.0.1")]
    public partial class pidwsdocPortClient : System.ServiceModel.ClientBase<org.openoces.ooapi.pidservice.impl.pidwsdocPort>, org.openoces.ooapi.pidservice.impl.pidwsdocPort
    {
        
    /// <summary>
    /// Implement this partial method to configure the service endpoint.
    /// </summary>
    /// <param name="serviceEndpoint">The endpoint to configure</param>
    /// <param name="clientCredentials">The client credentials</param>
    static partial void ConfigureEndpoint(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Description.ClientCredentials clientCredentials);
        
        public pidwsdocPortClient() : 
                base(pidwsdocPortClient.GetDefaultBinding(), pidwsdocPortClient.GetDefaultEndpointAddress())
        {
            this.Endpoint.Name = EndpointConfiguration.pidwsdocPort.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public pidwsdocPortClient(EndpointConfiguration endpointConfiguration) : 
                base(pidwsdocPortClient.GetBindingForEndpoint(endpointConfiguration), pidwsdocPortClient.GetEndpointAddress(endpointConfiguration))
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public pidwsdocPortClient(EndpointConfiguration endpointConfiguration, string remoteAddress) : 
                base(pidwsdocPortClient.GetBindingForEndpoint(endpointConfiguration), new System.ServiceModel.EndpointAddress(remoteAddress))
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public pidwsdocPortClient(EndpointConfiguration endpointConfiguration, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(pidwsdocPortClient.GetBindingForEndpoint(endpointConfiguration), remoteAddress)
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public pidwsdocPortClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress)
        {

        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<org.openoces.ooapi.pidservice.impl.pidResponse> org.openoces.ooapi.pidservice.impl.pidwsdocPort.pidAsync(org.openoces.ooapi.pidservice.impl.pidRequest1 request)
        {
            return base.Channel.pidAsync(request);
        }
        
        public System.Threading.Tasks.Task<org.openoces.ooapi.pidservice.impl.pidResponse> pidAsync(System.Collections.Generic.List<org.openoces.ooapi.pidservice.impl.PIDRequest> pIDRequests)
        {
            org.openoces.ooapi.pidservice.impl.pidRequest1 inValue = new org.openoces.ooapi.pidservice.impl.pidRequest1();
            inValue.Body = new org.openoces.ooapi.pidservice.impl.pidRequest1Body();
            inValue.Body.pIDRequests = pIDRequests;
            return ((org.openoces.ooapi.pidservice.impl.pidwsdocPort)(this)).pidAsync(inValue);
        }
        
        public System.Threading.Tasks.Task<int> testConnectionAsync(int intVal)
        {
            return base.Channel.testConnectionAsync(intVal);
        }
        
        public System.Threading.Tasks.Task testAsync()
        {
            return base.Channel.testAsync();
        }
        
        public virtual System.Threading.Tasks.Task OpenAsync()
        {
            return System.Threading.Tasks.Task.Factory.FromAsync(((System.ServiceModel.ICommunicationObject)(this)).BeginOpen(null, null), new System.Action<System.IAsyncResult>(((System.ServiceModel.ICommunicationObject)(this)).EndOpen));
        }
        
        public virtual System.Threading.Tasks.Task CloseAsync()
        {
            return System.Threading.Tasks.Task.Factory.FromAsync(((System.ServiceModel.ICommunicationObject)(this)).BeginClose(null, null), new System.Action<System.IAsyncResult>(((System.ServiceModel.ICommunicationObject)(this)).EndClose));
        }
        
        private static System.ServiceModel.Channels.Binding GetBindingForEndpoint(EndpointConfiguration endpointConfiguration)
        {
            if ((endpointConfiguration == EndpointConfiguration.pidwsdocPort))
            {
                System.ServiceModel.BasicHttpBinding result = new System.ServiceModel.BasicHttpBinding();
                result.MaxBufferSize = int.MaxValue;
                result.ReaderQuotas = System.Xml.XmlDictionaryReaderQuotas.Max;
                result.MaxReceivedMessageSize = int.MaxValue;
                result.AllowCookies = true;
                return result;
            }
            throw new System.InvalidOperationException(string.Format("Could not find endpoint with name \'{0}\'.", endpointConfiguration));
        }
        
        private static System.ServiceModel.EndpointAddress GetEndpointAddress(EndpointConfiguration endpointConfiguration)
        {
            if ((endpointConfiguration == EndpointConfiguration.pidwsdocPort))
            {
                return new System.ServiceModel.EndpointAddress("http://localhost:8080/pid_serviceprovider_server/pidws/");
            }
            throw new System.InvalidOperationException(string.Format("Could not find endpoint with name \'{0}\'.", endpointConfiguration));
        }
        
        private static System.ServiceModel.Channels.Binding GetDefaultBinding()
        {
            return pidwsdocPortClient.GetBindingForEndpoint(EndpointConfiguration.pidwsdocPort);
        }
        
        private static System.ServiceModel.EndpointAddress GetDefaultEndpointAddress()
        {
            return pidwsdocPortClient.GetEndpointAddress(EndpointConfiguration.pidwsdocPort);
        }
        
        public enum EndpointConfiguration
        {
            
            pidwsdocPort,
        }
    }
}
