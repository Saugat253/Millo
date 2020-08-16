using DeLoachAero.WebApi;
using Millo.Constraints;
using Millo.Exceptions;
using Millo.Filters;
using Millo.Filters.AuthenticationFilter;
using Millo.Filters.ExceptionFilters;
using Millo.Handlers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Http.ExceptionHandling;
using System.Web.Http.Routing;

namespace Millo
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services


            // Web API configuration and services
            //for supressing the Authentication system defaulted by IIS server. 
            //this will enable web api authentication, written in our code.
            // host principal means Authentication Principal of IIS server not our API authentication.
            config.SuppressHostPrincipal();
            // Web API routes
            var constraintResolver = new DefaultInlineConstraintResolver();
            constraintResolver.ConstraintMap.Add("enum", typeof(EnumerationConstraint));
            config.MapHttpAttributeRoutes(constraintResolver);
            config.MessageHandlers.Add(new FullPipelineMessageHandler());
            config.Filters.Add(new ClientCacheControlFilterAttribute(ClientCacheControl.Private, 2));
            config.Filters.Add(new RouteTimerFilterAttribute());
            config.Filters.Add(new ValidateModelStateAttribute());
            config.MessageHandlers.Add(new ForwardedHeadersHandler());
            config.MessageHandlers.Add(new RemoveBadHeadersHandlers());
            config.MessageHandlers.Add(new ApiKeyHeaderHandler());
            config.Filters.Add(new RequireHttpsAttribute());

            // Exception Handling 
            config.Services.Add(typeof(IExceptionLogger), new GlobalExceptionLogger());
            //config.Services.Replace(typeof(IExceptionHandler), new GlobalExceptionHandler());

            //RFC 7807 global handler and base Uri for exception types.
            config.Services.Replace(typeof(IExceptionHandler), new RFC7807GlobalExceptionHandler());
            RFC7807Exception.TypeUriAuthority = "https://www.example.com/probs/";

            config.Filters.Add(new NotImplementedExceptionFilter());

            config.Filters.Add(new BasicAuthFilterAttribute());



            //config.Routes.MapHttpRoute(
            //    name: "DefaultApi",
            //    routeTemplate: "api/{controller}/{id}",
            //    defaults: new { id = RouteParameter.Optional }
            //);
        }
    }
}
