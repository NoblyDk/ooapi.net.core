using System;
using System.ServiceModel;
using System.Threading.Tasks;
using System.Net.Http;
using System.Threading;
using System.ServiceModel.Channels;

namespace ooapi.net.core.ooapi.utils
{
    class CustomHttpBinding : BasicHttpsBinding
    {
        public override BindingElementCollection CreateBindingElements()
        {
            var elements = base.CreateBindingElements();
            var transport = elements.Find<HttpsTransportBindingElement>();
            if (transport != null)
            {
                elements.Remove(transport);
                elements.Add(CustomHttpsTransportBindingElement.CreateFromHttpsTransportBindingElement(transport));
            }
            return elements;
        }
    }

    class CustomHttpsTransportBindingElement : HttpsTransportBindingElement
    {
        private Func<HttpClientHandler, HttpMessageHandler> _createDelegatingHandler = client => new CustomHttpMessageHandler(client);
        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingContext context)
        {
            context.BindingParameters.Add(_createDelegatingHandler);
            return base.BuildChannelFactory<TChannel>(context);
        }

        public override BindingElement Clone()
        {
            return CreateFromHttpsTransportBindingElement(this);
        }

        public static CustomHttpsTransportBindingElement CreateFromHttpsTransportBindingElement(HttpsTransportBindingElement from)
        {
            return new CustomHttpsTransportBindingElement
            {
                AllowCookies = from.AllowCookies,
                AuthenticationScheme = from.AuthenticationScheme,
                BypassProxyOnLocal = from.BypassProxyOnLocal,
                ManualAddressing = from.ManualAddressing,
                MaxBufferSize = from.MaxBufferSize,
                MaxReceivedMessageSize = from.MaxReceivedMessageSize,
                ProxyAddress = from.ProxyAddress,
                ProxyAuthenticationScheme = from.ProxyAuthenticationScheme,
                RequireClientCertificate = from.RequireClientCertificate,
                TransferMode = from.TransferMode,
                UseDefaultWebProxy = from.UseDefaultWebProxy,
                WebSocketSettings = from.WebSocketSettings
            };
        }
    }

    class CustomHttpMessageHandler : DelegatingHandler
    {
        public CustomHttpMessageHandler(HttpMessageHandler innerHandler) : base(innerHandler)
        {
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.ExpectContinue = false;
            return base.SendAsync(request, cancellationToken);
        }
    }
}
