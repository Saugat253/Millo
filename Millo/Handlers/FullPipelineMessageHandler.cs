using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Millo.Handlers
{
    public class FullPipelineMessageHandler : DelegatingHandler
    {
        const string _header = "full-Pipeline-Timer";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            var timer = Stopwatch.StartNew();
            var response = await base.SendAsync(request, token);
            var elapsed = timer.ElapsedMilliseconds;
            Trace.WriteLine(_header + elapsed + "msec");
            response.Headers.Add(_header, elapsed + "msec");
            return response;
        }
    }
    
}