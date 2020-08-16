using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Millo.Handlers
{
    public class RemoveBadHeadersHandlers : DelegatingHandler
    {
        // Names of headers to remove
        readonly string[] _badHeaders = { "X-Powered-By", "X-AspNet-Version", "Server" };
        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Call the rest of the Pipeline all the way to the response Message
            var response = await base.SendAsync(request, cancellationToken);
            // now at this step all process has been executed and we can remove the bad headers which will give information to attacker..
            foreach (var header in _badHeaders)
            {
                response.Headers.Remove(header);
            }
            // return the final bad header removed message to client..
            return response;
        }
    }
}