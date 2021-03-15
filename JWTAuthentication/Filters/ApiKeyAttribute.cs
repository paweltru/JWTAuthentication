using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication.Filters
{
    [AttributeUsage(validOn: AttributeTargets.Class | AttributeTargets.Method)]
    public class ApiKeyAttribute : Attribute, IAsyncActionFilter
    {
        private const string ApiKeyName = "X-APIKEY";
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var routeVals = context.ActionDescriptor.RouteValues;

            if (routeVals.ContainsKey("controller") && routeVals["controller"].Equals("Identity"))
            { }
            else
            {
                if (context.HttpContext.User.Identity.IsAuthenticated) { }
                else
                {
                    if (!context.HttpContext.Request.Headers.TryGetValue(ApiKeyName, out var extractedApiKey))
                    {
                        context.Result = new ContentResult()
                        {
                            StatusCode = 401,
                            Content = "Api Key was not provided"
                        };
                        return;
                    }

                    var appSettings = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();

                    var apiKey = appSettings.GetValue<string>(ApiKeyName);

                    if (!apiKey.Equals(extractedApiKey))
                    {
                        context.Result = new ContentResult()
                        {
                            StatusCode = 401,
                            Content = "Api Key is not valid"
                        };
                        return;
                    }
                }

            }


            await next();
        }
    }
}
