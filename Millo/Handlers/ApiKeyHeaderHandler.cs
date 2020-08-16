using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Millo.Handlers
{
    public class ApiKeyHeaderHandler : DelegatingHandler
    {

        public const string _ApiKeyHeader = "X-Api-Key";
        public const string _ApiQueryString = "api_key";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            #region Before Pipeline
            string apiKey = null;
            // if the request comes from swagger abort the further process
            //if (request.RequestUri.Segments[1].ToLowerInvariant().StartsWith("swagger"))
            //    return base.SendAsync(request, token);
            // checks if the Api Key is in the Header....
            if (request.Headers.Contains(_ApiKeyHeader))
            {
                apiKey = request.Headers.GetValues(_ApiKeyHeader).FirstOrDefault();

            }
            // if the Api Key is not in the Header lets check on the query string it may be included on the query string..
            else
            {
                var queryString = request.GetQueryNameValuePairs();
                var kvp = queryString.FirstOrDefault(a => a.Key.ToLowerInvariant().Equals(_ApiQueryString));
                if (!string.IsNullOrEmpty(kvp.Value))
                    apiKey = kvp.Value;
            }
            // was Api key present? if not then abort the request..
            //if (string.IsNullOrEmpty(apiKey))
            //{
            //    var response = new HttpResponseMessage(HttpStatusCode.Forbidden)
            //    {
            //        Content = new StringContent("missing api key")
            //    };
            //    return Task.FromResult(response);
            //}
            // save the value to properties
            request.Properties.Add(_ApiKeyHeader, apiKey);
            #endregion Before Pipeline
            return base.SendAsync(request, token);
            #region after Pipeline
            #endregion  after Pipeline
        }


    }
    public static class HttpRequestMessageApiKeyExtension
    {
        public static string GetApiKey(this HttpRequestMessage httpRequestMessage)
        {
            if (httpRequestMessage == null)
                return null;
            if (httpRequestMessage.Properties.TryGetValue(ApiKeyHeaderHandler._ApiKeyHeader, out object apiKey))
                return (string)apiKey;

            return null;
        }
    }
}