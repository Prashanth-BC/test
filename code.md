```csharp
// FILEPATH: ./IProvideRequestHeaders.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Specialized;


namespace SLDBService
{
    public interface IProvideRequestHeaders
    {
        IHeaderDictionary Headers { get; }

        string GetSessionId();
    }
}
```

```csharp
// FILEPATH: ./SLDBUtil.cs
using Microsoft.ApplicationInsights;

namespace SLDBService.Util{

    public class SLDBUtil{
        private static TelemetryClient _logger;
        public  static TelemetryClient Logger { get => _logger; }
        public static void Init(TelemetryClient logger){
            _logger = logger;
        } 
    }
}```

```csharp
// FILEPATH: ./IEnumerableExtensions.cs
using System;
using System.Collections.Generic;

namespace SLDBService
{
    public static class IEnumerableExtensions
    {
        public static IEnumerable<TSource> DistinctBy<TSource, TKey>(this IEnumerable<TSource> source, Func<TSource, TKey> keySelector, IEqualityComparer<TKey> comparer = null)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (keySelector == null) throw new ArgumentNullException(nameof(keySelector));

            return innerDistinctBy(); 
            
            IEnumerable<TSource> innerDistinctBy()
            {
                var knownKeys = new HashSet<TKey>(comparer);
                foreach (var element in source)
                {
                    if (knownKeys.Add(keySelector(element)))
                        yield return element;
                }
            }
        }
    }
}
```

```csharp
// FILEPATH: ./ISLDBReset.cs
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService
{
    public interface ISLDBReset
    {
        /// <summary>
        /// Reads the boolean value stored in platform storage with key "SLDBReset".
        /// If key is not present yet, the key will be created.
        /// </summary>
        Task<bool> ShouldReset();

        /// <summary>
        /// Writes the string value stored in platform storage with key "SLDBVersionBeforeReset" to given <paramref name="sldbVersion"/> and also writes
        /// the value for key "SLDBResetRequested" to current UTC dateTime in unix time format.
        /// </summary>
        Task ConfirmReset(string sldbVersion);

        /// <summary>
        /// Writes the string value stored in platform storage with key "SLDBVersionAfterReset" to given <paramref name="sldbVersion"/> and also writes
        /// the value for key "SLDBReset" to false.
        /// </summary>
        Task FinishReset(string sldbVersion);
    }
}
```

```csharp
// FILEPATH: ./Certificates.cs
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SLDBService
{
    public interface ICertificates{
        public  X509Certificate2 GetCertificateCurrentUser(string thumbprint);
    }
    public class Certificates : ICertificates
    {
        /// <summary>
        /// Provide a certificate based on certificate thumbprint from current user.
        /// </summary>
        /// <param name="thumbprint">thumbprint of certificate</param>
        /// <returns>return the certificate in case of success, otherwise null</returns>
        /// <exception cref="ArgumentNullException">In case thumbprint is not valid</exception>
        static X509Certificate2 userCertificate = null;
        static Object syncObject = new object();
        public X509Certificate2 GetCertificateCurrentUser(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
                throw new ArgumentNullException("thumbprint", "Argument 'thumbprint' cannot be 'null' or 'string.empty'");

            if (userCertificate == null)
            {
                lock (syncObject)
                {
                    if (userCertificate != null)
                    {
                        return userCertificate;
                    }

                    X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    certStore.Open(OpenFlags.ReadOnly);

                    X509Certificate2Collection certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                    if (certCollection.Count > 0)
                    {
                        userCertificate = certCollection[0];
                    }

                    certStore.Close();

                    return userCertificate;
                }
            }
            return userCertificate;
        }
    }
    
    public class FakeCertificates : ICertificates
    {
        public X509Certificate2 GetCertificateCurrentUser(string thumbprint)
        {
            return new X509Certificate2();
        }
    }
}```

```csharp
// FILEPATH: ./LoggingBehavior.cs
using MediatR;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Http;

namespace SLDBService
{
    /// <summary>
    /// Pipeline behavior that logs request/response data or exception details, if request fails with exception.
    /// </summary>
    /// <typeparam name="TRequest"></typeparam>
    /// <typeparam name="TResponse"></typeparam>
    public class LoggingBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
        where TRequest : IRequest<TResponse>
    {
        private TelemetryClient Logger { get; }
        public IProvideRequestHeaders RequestHeadersProvider { get; set; }

        /// <summary>
        /// Initializes new instance of logging behavior with given logger.
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="requestHeadersProvider"></param>
        public LoggingBehavior(TelemetryClient logger, IProvideRequestHeaders requestHeadersProvider)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            RequestHeadersProvider =
                requestHeadersProvider ?? throw new ArgumentNullException(nameof(requestHeadersProvider));
        }

        /// <summary>
        /// Handles the request
        /// </summary>
        /// <param name="request"></param>
        /// <param name="cancellationToken"></param>
        /// <param name="next"></param>
        /// <returns></returns>
        public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next,
            CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            var correlationToken = Guid.NewGuid();

            try
            {
                // Log the request before executing
                Logger.TrackTrace(
                    $"{typeof(TRequest).Name}",
                    SeverityLevel.Information,
                    new Dictionary<string, string>
                    {
                        { "CorrelationToken", correlationToken.ToString() },
                        { "SessionId", RequestHeadersProvider.GetSessionId() },
                        { "RawJson", JsonConvert.SerializeObject(request) }
                    });

                // execute request
                var response = await next().ConfigureAwait(false);

                // Log response
                Logger.TrackTrace(
                    $"{typeof(TResponse).Name}",
                    SeverityLevel.Information,
                    new Dictionary<string, string>
                    {
                        { "CorrelationToken", correlationToken.ToString() },
                        { "SessionId", RequestHeadersProvider.GetSessionId() },
                        { "ProcessingTime", stopwatch.ElapsedMilliseconds.ToString() },
                        { "RawJson", JsonConvert.SerializeObject(response) }
                    });

                return response;
            }
            catch (Exception ex)
            {
                // Log exception
                Logger.TrackException(
                    ex,
                    new Dictionary<string, string>
                    {
                        { "CorrelationToken", correlationToken.ToString() },
                        { "SessionId", RequestHeadersProvider.GetSessionId() },
                        { "ProcessingTime", stopwatch.ElapsedMilliseconds.ToString() }
                    });

                throw;
            }
        }
    }

    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private TelemetryClient Logger { get; }


        public RequestLoggingMiddleware(RequestDelegate next, TelemetryClient logger)
        {
            _next = next;
            Logger = logger;

        }

        public async Task Invoke(HttpContext context)
        {
            if (context.Request != null && context.Request.Body != null)
            {
                try
                {
                    context.Request.EnableBuffering(); // Enables reading the request body multiple times

                    string requestBody = await ReadRequestBodyAsync(context.Request);

                    if (Logger != null)
                    {
                        var properties = new Dictionary<string, string>
                        {
                            { "method", context.Request.Method.ToString() },
                            { "path", context.Request.Path.ToString() }
                        };
                        context.Request.Headers.ToList().ForEach(x => properties.Add(x.Key, x.Value));
                        Logger.TrackTrace(
                            $"Request: {requestBody}",properties: properties);
                    }
                }
                catch
                {
                }

                context.Request.Body.Position = 0; // Resets the position of the request body stream
            }

            await _next(context);
        }

        private async Task<string> ReadRequestBodyAsync(HttpRequest request)
        {
            try
            {
                using (StreamReader reader = new StreamReader(request.Body, Encoding.UTF8, true, 1024, true))
                {
                    return await reader.ReadToEndAsync();
                }
            }
            catch
            {
            }

            try
            {
                using (StreamReader reader = new StreamReader(request.Body, Encoding.Unicode, true, 1024, true))
                {
                    Logger.TrackTrace($"Trying to read request body with Unicode encoding");
                    return await reader.ReadToEndAsync();
                }
            }
            catch
            {
            }

            return "Unable to read request body";
        }
    }

    public class CaptureClientIpAddress : ITelemetryInitializer
    {
        public void Initialize(ITelemetry telemetry)
        {
            var clientIPValue = telemetry.Context.Location.Ip;
            if(telemetry is ISupportProperties propTelemetry )
            {
                if (!propTelemetry.Properties.ContainsKey("client-ip"))
                {
                    propTelemetry.Properties.Add("client-ip", clientIPValue);    
                }
                propTelemetry.Properties.Add("custom-client-ip", clientIPValue);
            }
            
        }
    }
}```

```csharp
// FILEPATH: ./ProvideRequestHeaders.cs
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http.Headers;

namespace SLDBService
{
    public class ProvideRequestHeaders : IProvideRequestHeaders
    {
        public ProvideRequestHeaders(IHeaderDictionary headers)
        {
            Headers = headers;
        }

        public IHeaderDictionary Headers { get; }

        public string GetSessionId()
        {
            if (Headers != null)
            {
                if (Headers.ContainsKey("X-SessionId"))
                {
                    return Headers["X-SessionId"];
                }
                else
                {
                    return "NO_SESSION";
                }
            }

            return "NO_HEADERS";
        }
    }
}
```

```csharp
// FILEPATH: ./SLDBConfiguration.cs
using System;
using System.Collections.Generic;

namespace SLDBService{

internal static class SLDBConfiguration{
public static string SLOT_NAME = "Default";//This is set in the startup.cs using SLOT_NAME from appsettings.json
public static int TIMEOUT_IN_MINUTES = 5;//This is set in the startup.cs using TIMEOUT_IN_MINUTES from appsettings.json

public static string REDIS_CONNECTION_STRING = "";//This is set in the startup.cs using redisConnection from appsettings.json

 public static bool EnableResponseLogging { get; set; } = false;

 public static bool EnableRequestLogging { get; set; } = false;

 public static bool SkipGenDomain { get; set; } = false;

 public static int GeoCoordinatePrecisionDigits { get; set; } = 2;

 public static List<int> CacheablePreparedStatementSourceQuerySeqNrList { get; set; } = new List<int>();

 public static List<int> CacheablePreparedStatementExecutionQuerySeqNrList { get; set; } = new List<int>();

 public static bool CacheUnkownStations{get;set;} = false;
 
 public static int RequestTimeOutInSeconds { get; set; } = 5;

 public static int UnknownStationsBatchSize { get; set; } = 100;

}
}```

```csharp
// FILEPATH: ./Startup.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.ApplicationInsights;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http;
using Microsoft.OpenApi.Models;
using MediatR;
using System.Reflection;
using SLDBService.ErrorHandler;
using Newtonsoft.Json.Serialization;
using Newtonsoft.Json;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.WindowsAzure.Storage.Table;
using Microsoft.WindowsAzure.Storage;
using System.Globalization;
using Dapper;
using SLDBService.StatementMetadata;
using Microsoft.ApplicationInsights.AspNetCore.Extensions;

namespace SLDBService
{
    public class AppInfoTableEntity : TableEntity
    {
        public AppInfoTableEntity(string partitionKey, string rowKey) : base(partitionKey, rowKey)
        {
        }

        public string description { get; set; }
    }
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }


        public IConfiguration Configuration { get; }


        private async Task StoreAppInfo()
        {
            var account = CloudStorageAccount.Parse(Configuration.GetSection("appSettings")["UnknownStationStorageConnection"]);
            var client = account.CreateCloudTableClient();
            var table = client.GetTableReference("appinfo");
            var tableExists = await table.ExistsAsync().ConfigureAwait(false);
            if (!tableExists)
            {
                await table.CreateAsync().ConfigureAwait(false);
            }
            var PartitionKey = DateTime.UtcNow.ToString("yyyy-MM-dd", DateTimeFormatInfo.CurrentInfo);
            var RowKey = DateTime.UtcNow.ToString("yyyy-MM-dd", DateTimeFormatInfo.CurrentInfo);
            var entity = new AppInfoTableEntity(PartitionKey, RowKey);
            entity.description = $"Branch:{ThisAssembly.Git.Branch}, CommitDate:{ThisAssembly.Git.CommitDate}, Commits:{ThisAssembly.Git.Commits},  Tag:{ThisAssembly.Git.BaseTag}, SHA:{ThisAssembly.Git.Sha}, Commits pending:{ThisAssembly.Git.IsDirtyString}";
            await table.ExecuteAsync(TableOperation.InsertOrReplace(entity)).ConfigureAwait(false);
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpContextAccessor();

            var options = new ApplicationInsightsServiceOptions();


            services.AddApplicationInsightsTelemetry(options);


            services.AddApplicationInsightsTelemetry();

            services.AddMediatR(cfg =>
            {
                cfg.RegisterServicesFromAssembly(typeof(Program).Assembly);
            });

            services.AddControllers()

                .AddNewtonsoftJson(opts =>
                {
                    opts.SerializerSettings.ContractResolver = new DefaultContractResolver();
                    opts.SerializerSettings.Formatting = Formatting.None;
                });//Use NewtonsoftJson for deserialization which is not very strict as system.text.json.
                   //Otherwise reuest will be failed as some of the request we are getting contains numbers as string.
                   //To be abled to use the stricter version of json deserializer we need code in the head unit to be changed.

            services.AddMvc(c =>
            {
                c.EnableEndpointRouting = false;
                FilterConfig.RegisterGlobalFilters(c.Filters);
            }).AddControllersAsServices()
            .AddNewtonsoftJson(opts =>
            {
                opts.SerializerSettings.ContractResolver = new DefaultContractResolver();
                opts.SerializerSettings.Formatting = Formatting.None;
            });//Use NewtonsoftJson for deserialization which is not very strict as system.text.json.
               //Otherwise reuest will be failed as some of the request we are getting contains numbers as string.
               //To be abled to use the stricter version of json deserializer we need code in the head unit to be changed.

            var appSettings = Configuration.GetSection("appSettings");


            var sqlConnectionString = Configuration.GetConnectionString("SLDB");
            using (
                var sqlConnection = new System.Data.SqlClient.SqlConnection(sqlConnectionString))
            {
                //Create table if not exists with the name of the commonCacheTable with columns named colKey of BIGINT and colValue of NVARCHAR(MAX). colKey is the primary key.
                var tables = new List<string> { "commonCacheTable", "unknownStationsCacheTable", "nonSqlCacheTable" };

                foreach (var tableName in tables)
                {
                    sqlConnection.Execute($@"IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[{tableName}]') AND type in (N'U'))
                        CREATE TABLE [dbo].[{tableName}]([colKey] [bigint] NOT NULL,[colValue] [nvarchar](max) NULL,CONSTRAINT [PK_{tableName}] PRIMARY KEY CLUSTERED ([colKey] ASC))");
                }


            }


            var disableTelemetryForDependency = false;
            if (!string.IsNullOrEmpty(appSettings["SLOT_NAME"]))
            {
                SLDBConfiguration.SLOT_NAME = appSettings["SLOT_NAME"];
            }
            if (!string.IsNullOrEmpty(appSettings["TIMEOUT_IN_MINUTES"]))
            {
                SLDBConfiguration.TIMEOUT_IN_MINUTES = int.Parse(appSettings["TIMEOUT_IN_MINUTES"]);
            }

            if (!string.IsNullOrEmpty(appSettings["RedisConnectionString"]))
            {

                SLDBConfiguration.REDIS_CONNECTION_STRING = appSettings["RedisConnectionString"];
            }

            var strEnableResponseLogging = appSettings["EnableResponseLogging"];
            if (!String.IsNullOrEmpty(strEnableResponseLogging))
            {
                var enable = SLDBConfiguration.EnableResponseLogging = false;
                if (Boolean.TryParse(strEnableResponseLogging, out enable))
                {
                    SLDBConfiguration.EnableResponseLogging = enable;
                }

            }

            if (appSettings.GetChildren().Any(x => x.Key == "GeoCoordinatePrecisionDigits"))
            {
                SLDBConfiguration.GeoCoordinatePrecisionDigits = int.Parse(appSettings["GeoCoordinatePrecisionDigits"]);
            }

            var strSkipGenDomain = appSettings["SkipGenDomain"];
            if (!String.IsNullOrEmpty(strSkipGenDomain))
            {
                var skip = SLDBConfiguration.SkipGenDomain = false;
                if (Boolean.TryParse(strSkipGenDomain, out skip))
                {
                    SLDBConfiguration.SkipGenDomain = skip;
                }

            }


            if (appSettings.GetChildren().Any(x => x.Key == "DisableTelemetryForDependency"))
            {

                if (Boolean.Parse(appSettings["DisableTelemetryForDependency"]))
                {
                    Microsoft.ApplicationInsights.AspNetCore.Extensions.ApplicationInsightsServiceOptions aiOptions
                = new Microsoft.ApplicationInsights.AspNetCore.Extensions.ApplicationInsightsServiceOptions();
                    aiOptions.EnableDependencyTrackingTelemetryModule = false;
                    aiOptions.EnableQuickPulseMetricStream = true;
                    aiOptions.EnableAdaptiveSampling = true;
                    services.AddApplicationInsightsTelemetry(aiOptions);
                }
            }

            //Get the CacheUnknownStations from setting and add it into condfiguration.
            SLDBConfiguration.CacheUnkownStations = false;
            if (appSettings.GetChildren().Any(x => x.Key == "CacheUnknownStations"))
            {
                SLDBConfiguration.CacheUnkownStations = Boolean.Parse(appSettings["CacheUnknownStations"]);
            }

            if(appSettings.GetChildren().Any(x => x.Key == "UnknownStationsBatchSize"))
            {
                SLDBConfiguration.UnknownStationsBatchSize = int.Parse(appSettings["UnknownStationsBatchSize"]);
            }

            //Get the TIME_OUT_IN)_SECONDS from setting and add it into condfiguration.
            var strRequestTimeOutInSeconds = appSettings["RequestTimeOutInSeconds"];
            if (!String.IsNullOrEmpty(strRequestTimeOutInSeconds))
            {
                int requestTimeOutInSeconds = 0;
                if (Int32.TryParse(strRequestTimeOutInSeconds, out requestTimeOutInSeconds))
                {
                    SLDBConfiguration.RequestTimeOutInSeconds = requestTimeOutInSeconds;
                }
            }

            //Get the list of CacheablePreparedStatemtnsSeqNr from the appsettings.json and add them to the CacheablePreparedStatemtnsSeqNrList
            var CacheablePreparedStatementSourceQuerySeqNrList = appSettings["CacheablePreparedStatementSourceQuerySeqNrList"];
            if (!String.IsNullOrEmpty(CacheablePreparedStatementSourceQuerySeqNrList))
            {
                var cacheablePreparedStatementsSeqNrList = CacheablePreparedStatementSourceQuerySeqNrList.Split(',');
                foreach (var cacheablePreparedStatementsSeqNr in cacheablePreparedStatementsSeqNrList)
                {
                    int seqNr;
                    if (Int32.TryParse(cacheablePreparedStatementsSeqNr, out seqNr))
                    {
                        SLDBConfiguration.CacheablePreparedStatementSourceQuerySeqNrList.Add(seqNr);
                    }
                }
            }

            var strCacheablePreparedStatementExecutionQuerySeqNrList = appSettings["CacheablePreparedStatementExecutionQuerySeqNrList"];
            if (!String.IsNullOrEmpty(strCacheablePreparedStatementExecutionQuerySeqNrList))
            {
                var cacheablePreparedStatementsSeqNrList = strCacheablePreparedStatementExecutionQuerySeqNrList.Split(',');
                foreach (var cacheablePreparedStatementsSeqNr in cacheablePreparedStatementsSeqNrList)
                {
                    int seqNr;
                    if (Int32.TryParse(cacheablePreparedStatementsSeqNr, out seqNr))
                    {
                        SLDBConfiguration.CacheablePreparedStatementExecutionQuerySeqNrList.Add(seqNr);
                    }
                }
            }

            SwaggerConfig.ConfigureServices(services);

            services.AddRouting();

            /*
            var container = new Container();

            container.Configure(config =>
            {
                config.AddRegistry<IocRegistry>();
                config.Populate(services);
            });
            */
            IocRegistry.Register(services);
            Task.Run(async () =>
            {
                await StoreAppInfo().ConfigureAwait(false);
            }
            );

            //return container.GetInstance<IServiceProvider>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, TelemetryConfiguration configuration)
        {
            var appSettings = Configuration.GetSection("appSettings");
            var strDisableSampling = appSettings["DisableTelemetrySamplingForTraceAndException"];
            var disableSampling = false;


           
            if(appSettings.GetChildren().Any(x => x.Key == "LogMiddlewareRequest"))
            {
               if (Boolean.Parse(appSettings["LogMiddlewareRequest"]))
                {
                    app.UseMiddleware<RequestLoggingMiddleware>();
                }
            }

            app.UseMiddleware<InvalidPayloadMiddleware>();
            if (!String.IsNullOrEmpty(strDisableSampling) && Boolean.TryParse(strDisableSampling, out disableSampling) && disableSampling)
            {
                if (configuration != null)
                {
                    var builder = configuration.DefaultTelemetrySink.TelemetryProcessorChainBuilder;
                    builder.UseAdaptiveSampling(maxTelemetryItemsPerSecond: 5, excludedTypes: "Event;Trace;Exception");
                    builder.Build();
                }

            }

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            SwaggerConfig.Configure(app, env);

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                // Map dashboard routes.
                routes.MapRoute(
                    name: "DefaultApi",
                    template: "api/{controller}/{action}");
            });

            app.UseRouting();

            app.UseAuthorization();

        }
    }
}
```

```csharp
// FILEPATH: ./FakeSLDBReset.cs
using Microsoft.ApplicationInsights;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService
{
    public class FakeSLDBReset : ISLDBReset
    {
        public TelemetryClient Logger { get; }

        public SLDBResetModel _data = new SLDBResetModel
        {
            SLDBReset = false
        };

        public FakeSLDBReset(TelemetryClient logger)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Task<bool> ShouldReset()
        {
            try
            {
                //Logger.TrackTrace("Reading MOCK value of SLDBReset.");

                var currentData = _data;

                //Logger.TrackTrace($"SUCCESS: Reading MOCK value of SLDBReset. Value is {currentData.SLDBReset}");

                return Task.FromResult(currentData.SLDBReset);
            }
            catch(Exception ex)
            {
                //Logger.TrackTrace("FAILED: Reading MOCK value of SLDBReset.");
                //Logger.TrackException(ex);
                throw;
            }
        }

        public Task ConfirmReset(string sldbVersion)
        {
            try
            {
                //Logger.TrackTrace($"MOCK Confirm SLDB Reset retrieved. SLDBVersionBeforeReset retrieved from HU is {sldbVersion}");

                var currentData = _data;

                currentData.SLDBResetRequested = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                currentData.SLDBVersionBeforeReset = sldbVersion;

                _data = currentData;

                //Logger.TrackTrace("SUCCESS: MOCK Confirm SLDB Reset retrieved.");

                return Task.CompletedTask;
            }
            catch(Exception ex)
            {
                //Logger.TrackTrace("FAILED: MOCK Confirm SLDB Reset retrieved.");
                //Logger.TrackException(ex);
                throw;
            }
        }

        public Task FinishReset(string sldbVersion)
        {
            try
            {
                //Logger.TrackTrace($"MOCK Finish SLDB Reset retrieved. SLDBVersionAfterReset retrieved from HU is {sldbVersion}.");

                var currentData = _data;

                currentData.SLDBReset = false;
                currentData.SLDBVersionAfterReset = sldbVersion;

                _data = currentData;

                //Logger.TrackTrace("SUCCESS: MOCK Finish SLDB Reset retrieved.");

                return Task.CompletedTask;
            }
            catch(Exception ex)
            {
                //Logger.TrackTrace("FAILED: MOCK Finish SLDB Reset retrieved.");
                //Logger.TrackException(ex);
                throw;
            }
        }

        public void Restart()
        {
            _data = new SLDBResetModel();
        }

        public void SetSessionId(Guid sessionId)
        {
            _data.CurrentSessionId = sessionId;
        }

        public class SLDBResetModel
        {
            public SLDBResetModel()
            {
                SLDBReset = false;
            }

            public bool SLDBReset { get; set; }
            public string SLDBVersionBeforeReset { get; set; }
            public string SLDBVersionAfterReset { get; set; }

            /// <summary>
            /// UTC in unix time, when reset was requested
            /// </summary>
            public long SLDBResetRequested { get; set; }

            public Guid CurrentSessionId { get; set; }
        }
    }
}
```

```csharp
// FILEPATH: ./PlatformStorageAccess.cs
using Microsoft.ApplicationInsights;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace SLDBService
{
    public class PlatformStorageAccess : IPlatformStorageAccess
    {
        public class PlatformResult
        {
            public HttpStatusCode StatusCode { get; set; }

            public string Data { get; set; }

            public bool Success => ((int)StatusCode) >= 200 && ((int)StatusCode) < 300;
        }

        private class StorageObject
        {
            public string Key { get; set; }
            public string Value { get; set; }
        }

        public string PlatformBaseUrl { get; }
        public X509Certificate2 Certificate { get; }
        public IProvideRequestHeaders RequestHeadersProvider { get; }
        public TelemetryClient Logger { get; }
        public string AppId { get; }

        public PlatformStorageAccess(string platformBaseUrl, X509Certificate2 certificate, IProvideRequestHeaders requestHeadersProvider, TelemetryClient logger, string appId)
        {
            PlatformBaseUrl = platformBaseUrl ?? throw new ArgumentNullException(nameof(platformBaseUrl));
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            RequestHeadersProvider = requestHeadersProvider ?? throw new ArgumentNullException(nameof(requestHeadersProvider));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));

            if (string.IsNullOrWhiteSpace(appId))
            {
                throw new ArgumentException("Must not be empty.", nameof(appId));
            }
            AppId = appId;
        }


        public Task<PlatformResult> GetValue(string key)
        {
            return GetDataFromPlatform(key, AppId, RequestHeadersProvider.GetSessionId());
        }

        public Task<bool> SetValue(string key, string value)
        {
            return SetDataAtPlatform(key, AppId, RequestHeadersProvider.GetSessionId(), value);
        }

        private HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(Certificate);

            return new HttpClient(handler);
        }

        private async Task<PlatformResult> GetDataFromPlatform(string key, string appID, string sessionID)
        {
            using (HttpClient httpClient = CreateHttpClient())
            {
                //string userCar = "user/car";

                Uri uri = new Uri(new Uri(PlatformBaseUrl), string.Concat("store/session/", sessionID, "/", appID, "/", key, "/user/car"));
                var trackingID = Guid.NewGuid().ToString();

                httpClient.Timeout = TimeSpan.FromSeconds(5);
                httpClient.BaseAddress = uri;
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Add("X-TrackingId", trackingID);

                try
                {
                    var response = await httpClient.GetAsync("").ConfigureAwait(false);
                    //Logger.TrackTrace($"GetDataFromPlatformStorage: StatusCode returned: {response.StatusCode}");

                    if (response.IsSuccessStatusCode)
                    {
                        var jsonBase64 = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                        var valueBase64 = JsonConvert.DeserializeObject<string>(jsonBase64);

                        //Logger.TrackTrace($"GetDataFromPlatformStorage: Key={key} / Value(Base64)={valueBase64}");

                        try
                        {
                            return new PlatformResult
                            {
                                Data = Encoding.UTF8.GetString(Convert.FromBase64String(valueBase64)),
                                StatusCode = response.StatusCode
                            };
                        }
                        catch (Exception ex)
                        {
                            // if value cannot be parsed, return NotFound
                            Logger.TrackTrace($"ERROR GetDataFromPlatformStorage: Key={key} / Value(Base64)={valueBase64}. Value could not be parsed. Exception: " + ex.Message);
                            return new PlatformResult
                            {
                                StatusCode = HttpStatusCode.NotFound
                            };
                        }
                    }
                    else
                    {
                        return new PlatformResult
                        {
                            StatusCode = response.StatusCode
                        };
                    }
                }
                catch (Exception ex)
                {
                    //throw new ApplicationException(string.Concat("Exception occurred getting data from platform shadow.", ex.ToString()));
                    Logger.TrackTrace(ex.StackTrace, Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Critical);
                    return new PlatformResult
                    {
                        StatusCode = HttpStatusCode.NotFound
                    };
                }
            }
        }

        private async Task<bool> SetDataAtPlatform(string key, string appID, string sessionID, string data)
        {
            using (HttpClient httpClient = CreateHttpClient())
            {
                //string userCar = "user/car";

                Uri uri = new Uri(new Uri(PlatformBaseUrl), string.Concat("store/session/", sessionID, "/", appID, "/user/car"));
                var trackingID = Guid.NewGuid().ToString();

                httpClient.Timeout = TimeSpan.FromSeconds(5);
                httpClient.BaseAddress = uri;
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Add("X-TrackingId", trackingID);

                try
                {
                    var storageObject = new StorageObject
                    {
                        Key = key,
                        Value = Convert.ToBase64String(Encoding.UTF8.GetBytes(data))
                    };

                    var response = await HttpClientExtensions.PostAsJsonAsync(httpClient, "", storageObject).ConfigureAwait(false);
                    var result = response.IsSuccessStatusCode;
                    if (!result)
                    {
                        Logger.TrackTrace($"Error setting data at platform shadow. Http status code {response.StatusCode}.", Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error);
                    }
                    else
                    {
                        //Logger.TrackTrace($"Success setting data at platform shadow. Http status code {response.StatusCode}.");
                    }

                    return result;
                }
                catch (Exception ex)
                {
                    //Logger.TrackTrace($"Error setting data at platform shadow. Exception occured. {ex.ToString()}", Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error);
                    //throw new ApplicationException(string.Concat("Exception occurred setting data at platform shadow.", ex.ToString()));
                    Logger.TrackTrace(ex.StackTrace, Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Critical);
                    return false;
                }
            }
        }
    }
}
```

```csharp
// FILEPATH: ./IPlatformStorageAccess.cs
using Microsoft.ApplicationInsights;
using System;
using System.Linq;
using System.Threading.Tasks;
using static SLDBService.PlatformStorageAccess;

namespace SLDBService
{
    public interface IPlatformStorageAccess
    {
        Task<PlatformResult> GetValue(string key);
        Task<bool> SetValue(string key, string value);
    }
}
```

```csharp
// FILEPATH: ./InvalidPayloadMiddleware.cs
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

public class InvalidPayloadMiddleware
{
    private readonly RequestDelegate _next;

    public InvalidPayloadMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        // Check if the request method is POST
        if (context.Request.Method == HttpMethods.Post)
        {
            context.Request.EnableBuffering(); // Enables reading the request body multiple times
            
                // Read the request body
                var requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
                context.Request.Body.Position = 0; // Resets the position of the request body stream
                requestBody = requestBody.Trim();

                // Perform validation on the request body
                if (string.IsNullOrEmpty(requestBody) || requestBody[0] != '{' || requestBody[requestBody.Length - 1] != '}')
                {
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await context.Response.WriteAsync("Invalid request payload");
                    return;
                }
            
        }

        await _next(context);
    }
}
```

```csharp
// FILEPATH: ./SLDBReset.cs
using Microsoft.ApplicationInsights;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService
{
    public class SLDBReset : ISLDBReset
    {
        private const string SLDB_RESET_KEY = "SLDB_RESET";
        private const string SLDB_RESETREQUESTED_KEY = "SLDB_RESETREQUESTED";
        private const string SLDB_VERSIONBEFORE_KEY = "SLDB_VERSIONBEFORE";
        private const string SLDB_VERSIONAFTER_KEY = "SLDB_VERSIONAFTER";
        private const string SLDB_RESETEXECUTED_KEY = "SLDB_RESETEXECUTED";

        public IPlatformStorageAccess Storage { get; }
        public TelemetryClient Logger { get; }

        public SLDBReset(IPlatformStorageAccess storage, TelemetryClient logger)
        {
            Storage = storage ?? throw new ArgumentNullException(nameof(storage));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<bool> ShouldReset()
        {
            try
            {
                //Logger.TrackTrace("Reading value of SLDBReset from platform storage.");

                var result = await Storage.GetValue(SLDB_RESET_KEY).ConfigureAwait(false);

                if (result.Success)
                {
                    //Logger.TrackTrace($"SUCCESS: Reading value of SLDBReset from platform storage. Value is {result.Data}");

                    return result.Data == "1";
                }
                else
                {
                    if (result.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        Logger.TrackTrace($"Value of SLDBReset not found in platform storage. Initializing value at platform shadow with value = 0.");

                        await Storage.SetValue(SLDB_RESET_KEY, "0").ConfigureAwait(false);
                    }
                    else
                    {
                        Logger.TrackTrace($"ERROR: Reading value of SLDB_RESET from platform storage. StatusCode {result.StatusCode}", Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error);
                    }
                }

                return false;
            }
            catch(Exception ex)
            {
                Logger.TrackException(ex);

                throw;
            }
        }

        public async Task ConfirmReset(string sldbVersion)
        {
            try
            {
                //Logger.TrackTrace("Confirm SLDB Reset retrieved. Trying to update platform storage values SLDBVersionBeforeReset and SLDBResetRequested.");

                await Storage.SetValue(SLDB_RESETREQUESTED_KEY, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()).ConfigureAwait(false);
                await Storage.SetValue(SLDB_VERSIONBEFORE_KEY, sldbVersion).ConfigureAwait(false);

                //Logger.TrackTrace("SUCCESS: Confirm SLDB Reset retrieved. Trying to update platform storage values SLDBVersionBeforeReset and SLDBResetRequested.");
            }
            catch
            {
                Logger.TrackTrace("FAILED: Finish SLDB Reset retrieved. Error updating platform storage values SLDBVersionBeforeReset and SLDBResetRequested.");

                throw;
            }
        }

        public async Task FinishReset(string sldbVersion)
        {
            try
            {
                //Logger.TrackTrace("Finish SLDB Reset retrieved. Trying to update platform storage values SLDBVersionAfterReset, SLDBResetExecuted and SLDBReset.");

                await Storage.SetValue(SLDB_RESET_KEY, "0").ConfigureAwait(false);
                await Storage.SetValue(SLDB_RESETEXECUTED_KEY, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()).ConfigureAwait(false);
                await Storage.SetValue(SLDB_VERSIONAFTER_KEY, sldbVersion).ConfigureAwait(false);

                //Logger.TrackTrace("SUCCESS: Finish SLDB Reset retrieved. Trying to update platform storage values SLDBVersionAfterReset and SLDBReset.");
            }
            catch
            {
                Logger.TrackTrace("FAILED: Finish SLDB Reset retrieved. Error updating platform storage values SLDBVersionAfterReset and SLDBReset.");

                throw;
            }
        }
    }
}
```

```csharp
// FILEPATH: ./HttpClientExtensions.cs
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace SLDBService
{
    public static class HttpClientExtensions
    {
        public static Task<HttpResponseMessage> PostAsJsonAsync<T>(
            this HttpClient httpClient, string url, T data)
        {
            var dataAsString = JsonConvert.SerializeObject(data);
            var content = new StringContent(dataAsString);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return httpClient.PostAsync(url, content);
        }

        public static async Task<T> ReadAsJsonAsync<T>(this HttpContent content)
        {
            var dataAsString = await content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonConvert.DeserializeObject<T>(dataAsString);
        }
    }
}
```

```csharp
// FILEPATH: ./IUnknownStationsStorage.cs
using System.Threading;
using System.Threading.Tasks;
using SLDBService.Models;

namespace SLDBService.UnknownStation
{
    public interface IUnknownStationsStorage
    {
         Task<int> StoreRequest(UnknownStationRequest request, string reason, CancellationToken cancellationToken);
    }
}```

```csharp
// FILEPATH: ./IocRegistry.cs
using System;
using System.Linq;
using Dapper;
using MediatR;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SLDBService.Data;
using SLDBService.Handler.UnknownStation;
using SLDBService.Services.UnknownStation;
using SLDBService.StatementMetadata;
using SLDBService.UnknownStation;

namespace SLDBService
{
    /// <summary>
    /// Ioc container registry
    /// </summary>
    class HttpContextAccessorWrapper
    {
        public IHttpContextAccessor HttpContextAccessor { get; }
        public HttpContextAccessorWrapper(IHttpContextAccessor httpContextAccessor)
        {
            HttpContextAccessor = httpContextAccessor;
        }   
    }
    public class IocRegistry
    {

        /// <summary>
        /// Default constructor
        /// </summary>
        public static void Register(IServiceCollection services)
        {

            // Required MediatR registrations
            /*Scan(scanner =>
            {
                scanner.TheCallingAssembly();
                scanner.ConnectImplementationsToTypesClosing(typeof(IRequestHandler<>));
                scanner.ConnectImplementationsToTypesClosing(typeof(IRequestHandler<,>));
                scanner.ConnectImplementationsToTypesClosing(typeof(INotificationHandler<>));
            For<IMediator>().Use<Mediator>();
            });*/
            
            //For<ServiceFactory>().Use<ServiceFactory>(ctx => ctx.GetInstance);

            if(SLDBConfiguration.EnableResponseLogging){
                //For(typeof(IPipelineBehavior<,>)).Add(typeof(LoggingBehavior<,>));
                services.AddScoped(typeof(IPipelineBehavior<,>), typeof(LoggingBehavior<,>));

            }
            
            /*For<IProvideRequestHeaders>()
                .AlwaysUnique()
                .Use<ProvideRequestHeaders>("ProvideRequestHeaders factory", ctx =>
                {
                    var logger = ctx.GetInstance<TelemetryClient>();
                    var httpCtx = ctx.GetInstance<HttpContextAccessor>();

                    try
                    {
                        ProvideRequestHeaders result = null;
                        if ((null != httpCtx.HttpContext) && (null != httpCtx.HttpContext.Request))
                        {
                            result = new ProvideRequestHeaders(httpCtx.HttpContext.Request.Headers);
                        }
                        else
                        {
                            result = new ProvideRequestHeaders(null);
                        }
                        return result;
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of ProvideRequestHeaders object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
                });
                */
            services.AddScoped<HttpContextAccessorWrapper>();
            services.AddScoped<IProvideRequestHeaders,ProvideRequestHeaders>(ctx =>
            {
                
                var httpCtx = ctx.GetService<HttpContextAccessorWrapper>();
                var logger = ctx.GetService<TelemetryClient>();
                try
                    {
                        ProvideRequestHeaders result = null;
                        if ((null != httpCtx.HttpContextAccessor.HttpContext) && (null != httpCtx.HttpContextAccessor.HttpContext.Request))
                        {
                            result = new ProvideRequestHeaders(httpCtx.HttpContextAccessor.HttpContext.Request.Headers);
                        }
                        else
                        {
                            result = new ProvideRequestHeaders(null);
                        }
                        return result;
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of ProvideRequestHeaders object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
            });


            /*For<IPlatformStorageAccess>()
                .AlwaysUnique()
                .Use("PlatformStorageAccess factory", ctx =>
                {
                    var configuration = ctx.GetInstance<IConfiguration>();
                    var appSettings = configuration.GetSection("appSettings");
                    var baseUrl = appSettings["PlatformShadow"];
                    var certificateThumb = appSettings["WEBSITE_LOAD_CERTIFICATES"];
                    var appId = appSettings["ApplicationID"];



                    var logger = ctx.GetInstance<TelemetryClient>();

                    var certificate = Certificates.GetCertificateCurrentUser(certificateThumb);
                    if (certificate != null)
                    {
                        //logger.TrackTrace($"Certificate with thumbprint {certificate.Thumbprint} loaded successfully.");
                    }
                    else
                    {
                        logger.TrackTrace($"FAILED to load certificate with thumbprint {certificateThumb}.");
                    }

                    try
                    {
                        return new PlatformStorageAccess(baseUrl, certificate, ctx.GetInstance<IProvideRequestHeaders>(), logger, appId);
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of PlatformStorageAccess object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
                });*/
                
                services.AddScoped<IPlatformStorageAccess,PlatformStorageAccess>(ctx =>
                {
                    var configuration = ctx.GetService<IConfiguration>();
                    var appSettings = configuration.GetSection("appSettings");
                    var baseUrl = appSettings["PlatformShadow"];
                    var certificateThumb = appSettings["WEBSITE_LOAD_CERTIFICATES"];
                    var appId = appSettings["ApplicationID"];

                    var logger = ctx.GetService<TelemetryClient>();
                    ICertificates certificates = ctx.GetRequiredService<ICertificates>();
                    var certificate = certificates.GetCertificateCurrentUser(certificateThumb);
                    if (certificate != null)
                    {
                        //logger.TrackTrace($"Certificate with thumbprint {certificate.Thumbprint} loaded successfully.");
                    }
                    else
                    {
                        logger.TrackTrace($"FAILED to load certificate with thumbprint {certificateThumb}.");
                    }

                    try
                    {
                        return new PlatformStorageAccess(baseUrl, certificate, ctx.GetService<IProvideRequestHeaders>(), logger, appId);
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of PlatformStorageAccess object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
                });
            bool isRegistered = services.Any(serviceDescriptor =>
                serviceDescriptor.ServiceType == typeof(ICertificates));
            if (!isRegistered)
            {
            services.AddSingleton<ICertificates, Certificates>();
            }

            /*For<ISLDBReset>()
                .AlwaysUnique()
                .Use<SLDBReset>();
            */
            /*For<ISLDBReset>()
                .AlwaysUnique()
                .Use<ISLDBReset>("SLDB Reset", ctx =>
                {
                    var logger = ctx.GetInstance<TelemetryClient>();
                    var storage = ctx.GetInstance<IPlatformStorageAccess>();
                    var configuration = ctx.GetInstance<IConfiguration>();
                    var appSettings = configuration.GetSection("appSettings");

                    var useResetSLDBFeature = appSettings["UseResetSLDBFeature"];
                    Boolean enableSLDBReset = false;
                    if (!String.IsNullOrEmpty(useResetSLDBFeature) && Boolean.TryParse(useResetSLDBFeature, out enableSLDBReset) && enableSLDBReset)
                    {
                        return new SLDBReset(storage, logger);
                    }
                    return new FakeSLDBReset(logger);
                });*/
                services.AddScoped<ISLDBReset,ISLDBReset>(ctx =>
                {
                    var logger = ctx.GetService<TelemetryClient>();
                    var storage = ctx.GetService<IPlatformStorageAccess>();
                    var configuration = ctx.GetService<IConfiguration>();
                    var appSettings = configuration.GetSection("appSettings");

                    var useResetSLDBFeature = appSettings["UseResetSLDBFeature"];
                    Boolean enableSLDBReset = false;
                    if (!String.IsNullOrEmpty(useResetSLDBFeature) && Boolean.TryParse(useResetSLDBFeature, out enableSLDBReset) && enableSLDBReset)
                    {
                        return new SLDBReset(storage, logger);
                    }
                    return new FakeSLDBReset(logger);
                });

            /*For<IServiceTimeSharing>()
                .AlwaysUnique()
                .Use<ServiceTimeSharing>();*/
                services.AddTransient<IServiceTimeSharing,ServiceTimeSharing>();
                

            // HACK: For HU SLDB Reset testing only!
            //For<ISLDBReset>()
            //    .Singleton()
            //    .Use<FakeSLDBReset>();
            

            //Set the dapper command timeout to 2 seconds
            SqlMapper.Settings.CommandTimeout = 2;


            /*For<IConnectionFactory>()
                 .AlwaysUnique()
                .Use("Connection Factory", ctx =>
                {
                    var logger = ctx.GetInstance<TelemetryClient>();
                    try
                    {
                        var configuration = ctx.GetInstance<IConfiguration>();
                        return new SqlConnectionFactory(ConfigurationExtensions.GetConnectionString(configuration, "SLDB"));
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of ConnectionFactory object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
                });*/
                services.AddSingleton<ITelemetryInitializer, CaptureClientIpAddress>();
                services.AddSingleton<IConnectionFactory,IConnectionFactory>(ctx =>
                {
                    var logger = ctx.GetService<TelemetryClient>();
                    try
                    {
                        var configuration = ctx.GetService<IConfiguration>();
                        return new SqlConnectionFactory(ConfigurationExtensions.GetConnectionString(configuration, "SLDB"));
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of ConnectionFactory object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
                });

            /*For<IFindLogoId>()
                .AlwaysUnique()
                .Use<FindLogoId>();*/
                services.AddTransient<IFindLogoId,FindLogoId>();

            /*For<UnknownStationHandlerConfiguration>()
                .Use("UnknownStationHandlerConfiguration Factory", ctx =>
                {
                    var logger = ctx.GetInstance<TelemetryClient>();
                    try
                    {
                        var configuration = ctx.GetInstance<IConfiguration>();
                        return new UnknownStationHandlerConfiguration(configuration.GetSection("AppSettings")["UnknownStationStorageConnection"]);
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of UnknownStationHandlerConfiguration object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
                })
                .Singleton();*/
                services.AddSingleton<UnknownStationHandlerConfiguration>(ctx =>
                {
                    var logger = ctx.GetService<TelemetryClient>();
                    try
                    {
                        var configuration = ctx.GetService<IConfiguration>();
                        return new UnknownStationHandlerConfiguration(configuration.GetSection("AppSettings")["UnknownStationStorageConnection"]);
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of UnknownStationHandlerConfiguration object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
                });

            /*For<ConnectionMultiplexer>()
                .Use("ConnectionMultiplexer Factory",  ctx =>
                {
                    var logger = ctx.GetInstance<TelemetryClient>();
                     
                    
                    try
                    {
                        var configuration = ctx.GetInstance<IConfiguration>();
                        var appSettings = configuration.GetSection("appSettings");
                        Lazy<ConnectionMultiplexer> redisConnectionMultiplexer = null;
                        Task.Run(async () =>
                        {
                            redisConnectionMultiplexer = new Lazy<ConnectionMultiplexer> (await ConnectionMultiplexer.ConnectAsync(appSettings["RedisConnectionString"]));
                        }).Wait();
                        return redisConnectionMultiplexer.Value;
                    }
                    catch (Exception ex)
                    {
                        logger.TrackTrace("Creation of ConnectionMultiplexer object resulted in an exception: " + ex.Message);
                        logger.TrackException(ex);
                        throw;
                    }
                }).Singleton();
            */
            /*
            For<IResolveUnknownStation>().AlwaysUnique().Use<ResolveUnknownStationAM>();
            For<IResolveUnknownStation>().AlwaysUnique().Use<ResolveUnknownStationDAB>();
            For<IResolveUnknownStation>().AlwaysUnique().Use<ResolveUnknownStationFM>();
            For<IResolveUnknownStation>().AlwaysUnique().Use<ResolveUnknownStationDVB_T>();
            For<IResolveUnknownStation>().AlwaysUnique().Use<ResolveUnknownStationDVB_T2>();
            For<IResolveUnknownStation>().AlwaysUnique().Use<ResolveUnknownStationHD_AM>();
            For<IResolveUnknownStation>().AlwaysUnique().Use<ResolveUnknownStationHD_FM>();
            For<IResolveUnknownStation>().AlwaysUnique().Use<ResolveUnknownStationISDBT>();
            */
            services.AddScoped<IResolveUnknownStation,ResolveUnknownStationAM>();
            services.AddScoped<IResolveUnknownStation,ResolveUnknownStationDAB>();
            services.AddScoped<IResolveUnknownStation,ResolveUnknownStationFM>();
            services.AddScoped<IResolveUnknownStation,ResolveUnknownStationDVB_T>();
            services.AddScoped<IResolveUnknownStation,ResolveUnknownStationDVB_T2>();
            services.AddScoped<IResolveUnknownStation,ResolveUnknownStationHD_AM>();
            services.AddScoped<IResolveUnknownStation,ResolveUnknownStationHD_FM>();
            services.AddScoped<IResolveUnknownStation,ResolveUnknownStationISDBT>();
            // OPTIMIZE instead of registering scoped (=transient) repository that is doing db lookup each time,
            // return a warmed up thread-safe repository instance that caches all required information
            /*For<IPreparedStatementRepository>()
                .Use<PreparedStatementRepository>()
                .Singleton() ;*/
            services.AddSingleton<IPreparedStatementRepository,PreparedStatementRepository>();

            /*For<IServiceConfiguration>()
                .Use<ServiceConfiguration>();*/
            services.AddSingleton<IServiceConfiguration,ServiceConfiguration>();

            /*For<IScriptGlobals>()
                .Use<ScriptGlobals>();*/
                services.AddScoped<IScriptGlobals,ScriptGlobals>();

            /*For<IExecuteScripts>()
                .Use<ScriptExecution>();*/
            services.AddScoped<IExecuteScripts,ScriptExecution>();

            /*For<CompiledScriptCache>()
                .Singleton();*/
                services.AddSingleton<CompiledScriptCache>();

                services.AddSingleton<IUnknownStationsStorage,UnknownStationsStorage>();

            new CustomTypeHandlerRegistry().Register();
        }
    }
}```

```csharp
// FILEPATH: ./GlobalSuppressions.cs
// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1054:Uri parameters should not be strings", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.PlatformStorageAccess.#ctor(System.String,System.Security.Cryptography.X509Certificates.X509Certificate2,SLDBService.IProvideRequestHeaders,Microsoft.ApplicationInsights.TelemetryClient,System.String)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~F:SLDBService.SwaggerConfig.API_NAME")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.SwaggerConfig.ConfigureServices(Microsoft.Extensions.DependencyInjection.IServiceCollection)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.SwaggerConfig.GetXmlCommentsPath~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.SwaggerConfig.XSessionHeaderParameter")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.UnknownStation.UnknownStationRequestHandler.Handle(SLDBService.Models.UnknownStationRequest,System.Threading.CancellationToken)~System.Threading.Tasks.Task{SLDBService.Models.UnknownStationResponse}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1507:Use nameof to express symbol names", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Certificates.GetCertificateCurrentUser(System.String)~System.Security.Cryptography.X509Certificates.X509Certificate2")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.Logo.StationLogoRequestHandler.Handle(SLDBService.Models.StationLogoRequest,System.Threading.CancellationToken)~System.Threading.Tasks.Task{SLDBService.Models.StationLogoResponse}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Handler.VersionCheck.Logo.LogoDomainHandler.InnerLogoDomainHandler")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.Logo.LogoDomainHandler.ExecuteAsync(SLDBService.Models.BaseDataVersionCheckRequest,System.Version)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.ImageTransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.Logo.LogoDomainHandler.ImageMD5Base64(System.Byte[])~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5351:Do Not Use Broken Cryptographic Algorithms", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.Logo.LogoDomainHandler.ImageMD5Base64(System.Byte[])~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.PlatformStorageAccess.PlatformResult")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1056:Uri properties should not be strings", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.PlatformStorageAccess.PlatformBaseUrl")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.PlatformStorageAccess.CreateHttpClient~System.Net.Http.HttpClient")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2234:Pass system uri objects instead of strings", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.PlatformStorageAccess.GetDataFromPlatform(System.String,System.String,System.String)~System.Threading.Tasks.Task{SLDBService.PlatformStorageAccess.PlatformResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.PlatformStorageAccess.GetDataFromPlatform(System.String,System.String,System.String)~System.Threading.Tasks.Task{SLDBService.PlatformStorageAccess.PlatformResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ResolveUnknownStationAM.Resolve(System.Data.IDbConnection,SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{SLDBService.Services.UnknownStation.UnknownStationLookupResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Controllers.UrlHelperExtensions.HttpsAware(Microsoft.AspNetCore.Mvc.IUrlHelper)~Microsoft.AspNetCore.Mvc.IUrlHelper")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1825:Avoid zero-length array allocations.", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Data.ConditionParameterTypeHandler.Parse(System.Object)~SLDBService.StatementMetadata.ConditionParameter[]")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Controllers.SLDBController.Reset(System.String,SLDBService.Models.ResetSldbRequest)~System.Threading.Tasks.Task{Microsoft.AspNetCore.Mvc.IActionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1304:Specify CultureInfo", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Controllers.SLDBController.Reset(System.String,SLDBService.Models.ResetSldbRequest)~System.Threading.Tasks.Task{Microsoft.AspNetCore.Mvc.IActionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.RequestConditionParameter.ProvideSqlValue(SLDBService.StatementMetadata.StatementContext)~System.Threading.Tasks.Task{System.String}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Services.UnknownStation.ResolveUnknownStationDVB_T")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ResolveUnknownStationFM.Resolve(SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{SLDBService.Services.UnknownStation.UnknownStationLookupResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.Reset.ResetSldbRequestHandler.Handle(SLDBService.Models.ResetSldbRequest,System.Threading.CancellationToken)~System.Threading.Tasks.Task{SLDBService.Models.ResetSldbResponse}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.Reset.ResetSldbRequestHandler.Handle(SLDBService.Models.ResetSldbRequest,System.Threading.CancellationToken)~System.Threading.Tasks.Task{SLDBService.Models.ResetSldbResponse}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.FakeSLDBReset.SLDBResetModel")]

[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Services.UnknownStation.ResolveUnknownStationFM.Reason")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Services.UnknownStation.ResolveUnknownStationFMPI.Reason")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1040:Avoid empty interfaces", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Models.ISLDBTable")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "<Pending>", Scope = "member", Target = "~F:SLDBService.FakeSLDBReset._data")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1052:Static holder types should be Static or NotInheritable", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Program")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1054:Uri parameters should not be strings", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.HttpClientExtensions.PostAsJsonAsync``1(System.Net.Http.HttpClient,System.String,``0)~System.Threading.Tasks.Task{System.Net.Http.HttpResponseMessage}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Controllers.SLDBController.UnknownStation(System.String,SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{Microsoft.AspNetCore.Mvc.IActionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.BaseDataVersionCheckRequestHandler.Handle(SLDBService.Models.BaseDataVersionCheckRequest,System.Threading.CancellationToken)~System.Threading.Tasks.Task{SLDBService.Models.BaseDataVersionCheckResponse}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.BaseDataVersionCheckRequestHandler.HandleBaseDataDomainAsync(SLDBService.Models.BaseDataVersionCheckRequest)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.TransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.BaseDataVersionCheckRequestHandler.HandleGenreDomainAsync(SLDBService.Models.BaseDataVersionCheckRequest)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.TransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.BaseDataVersionCheckRequestHandler.HandleLogoDomainAsync(SLDBService.Models.BaseDataVersionCheckRequest)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.ImageTransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.BaseDataVersionCheckRequestHandler.HandleMetadataDomainAsync(SLDBService.Models.BaseDataVersionCheckRequest)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.TransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.BaseDataVersionCheckRequestHandler.HandlePhoneticDomainAsync(SLDBService.Models.BaseDataVersionCheckRequest)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.TransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.DomainHandler`1.GetTransactions(System.Data.IDbConnection,System.Collections.Generic.IEnumerable{SLDBService.StatementMetadata.PreparedStatement},SLDBService.StatementMetadata.StatementContext,System.Version)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.TransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.MuxVersionCheckRequestHandler.Handle(SLDBService.Models.MuxVersionCheckRequest,System.Threading.CancellationToken)~System.Threading.Tasks.Task{SLDBService.Models.MuxVersionCheckResponse}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.MuxVersionCheckRequestHandler.HandleMuxDomainAsync(SLDBService.Models.MuxVersionCheckRequest)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.TransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.ReceptionAreaVersionCheckRequestHandler.Handle(SLDBService.Models.ReceptionAreaVersionCheckRequest,System.Threading.CancellationToken)~System.Threading.Tasks.Task{SLDBService.Models.ReceptionAreaVersionCheckResponse}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.ReceptionAreaVersionCheckRequestHandler.HandleReceptionAreaDomainAsync(SLDBService.Models.ReceptionAreaVersionCheckRequest)~System.Threading.Tasks.Task{SLDBService.Handler.VersionCheck.TransactionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.HttpClientExtensions.PostAsJsonAsync``1(System.Net.Http.HttpClient,System.String,``0)~System.Threading.Tasks.Task{System.Net.Http.HttpResponseMessage}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.HttpClientExtensions.ReadAsJsonAsync``1(System.Net.Http.HttpContent)~System.Threading.Tasks.Task{``0}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.LoggingBehavior`2.Handle(`0,System.Threading.CancellationToken,MediatR.RequestHandlerDelegate{`1})~System.Threading.Tasks.Task{`1}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.PointInPolygonFinder.Contains(SLDBService.Services.UnknownStation.IReceptionAreaPolygon,System.Int32,System.Double)~System.Boolean")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ReceptionAreaPolygon.Create(System.String)~SLDBService.Services.UnknownStation.IReceptionAreaPolygon")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ReceptionAreaPolygonAngleDivisor36.#ctor(System.String)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ResolveUnknownStation.Resolve(SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{SLDBService.Services.UnknownStation.UnknownStationLookupResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ResolveUnknownStationFMnoPI.Resolve(System.Data.IDbConnection,SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{SLDBService.Services.UnknownStation.UnknownStationLookupResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ResolveUnknownStationFMPI.Resolve(System.Data.IDbConnection,SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{SLDBService.Services.UnknownStation.UnknownStationLookupResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ResolveUnknownStationHD_AM.Resolve(System.Data.IDbConnection,SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{SLDBService.Services.UnknownStation.UnknownStationLookupResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ResolveUnknownStationHD_FM.Resolve(System.Data.IDbConnection,SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{SLDBService.Services.UnknownStation.UnknownStationLookupResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.DBModelVersion(SLDBService.Models.UnknownStationRequest)~System.Version")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.ECC(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.EID(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.Frequency(SLDBService.Models.UnknownStationRequest)~System.Int32")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.GetTimestamp(SLDBService.Models.UnknownStationRequest)~System.Nullable{System.DateTimeOffset}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.ONID(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.SID(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.StationCallSign(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.TSID(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.VPLatDeg(SLDBService.Models.UnknownStationRequest)~System.Double")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.VPLongDeg(SLDBService.Models.UnknownStationRequest)~System.Double")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.ConditionParameter.CreateFrom(SLDBService.StatementMetadata.ConditionParameterEntity)~SLDBService.StatementMetadata.ConditionParameter")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.RequestParameter.ProvideSqlValue(SLDBService.StatementMetadata.StatementContext,System.Collections.Generic.IDictionary{System.String,System.Object})~System.Threading.Tasks.Task{System.String}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.ScriptConditionParameter.ProvideSqlValue(SLDBService.StatementMetadata.StatementContext)~System.Threading.Tasks.Task{System.String}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.ScriptParameter.ProvideSqlValue(SLDBService.StatementMetadata.StatementContext,System.Collections.Generic.IDictionary{System.String,System.Object})~System.Threading.Tasks.Task{System.String}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.SqlCommands.Parse(System.String)~SLDBService.StatementMetadata.SqlCommand")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.StatementParameter.CreateFrom(SLDBService.StatementMetadata.ParameterEntity)~SLDBService.StatementMetadata.StatementParameter")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.TableParameter.ProvideSqlValue(SLDBService.StatementMetadata.StatementContext,System.Collections.Generic.IDictionary{System.String,System.Object})~System.Threading.Tasks.Task{System.String}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1304:Specify CultureInfo", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.ConditionParameter.CreateFrom(SLDBService.StatementMetadata.ConditionParameterEntity)~SLDBService.StatementMetadata.ConditionParameter")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1304:Specify CultureInfo", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.SqlCommands.Parse(System.String)~SLDBService.StatementMetadata.SqlCommand")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1304:Specify CultureInfo", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.StatementParameter.CreateFrom(SLDBService.StatementMetadata.ParameterEntity)~SLDBService.StatementMetadata.StatementParameter")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.LoggingBehavior`2.Handle(`0,System.Threading.CancellationToken,MediatR.RequestHandlerDelegate{`1})~System.Threading.Tasks.Task{`1}")]

[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1307:Specify StringComparison", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Handler.VersionCheck.DomainHandler`1.DistinctExecutionQueryComparer.GetHashCode(SLDBService.StatementMetadata.PreparedStatement)~System.Int32")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1307:Specify StringComparison", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ReceptionAreaPolygon.Create(System.String)~SLDBService.Services.UnknownStation.IReceptionAreaPolygon")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.Station.FM_PI")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Services.UnknownStation.ResolveUnknownStationDVB_T2")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Services.UnknownStation.ResolveUnknownStationHD_AM")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Services.UnknownStation.ResolveUnknownStationHD_FM")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1716:Identifiers should not match keywords", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.IHttpRequestData.Get(System.String)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Controllers.SLDBController.StationLogo(System.String,System.Int32,System.Int32,System.Int32,System.Int32)~System.Threading.Tasks.Task{Microsoft.AspNetCore.Mvc.IActionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Models.BaseDataVersionCheckRequest.Get(System.String)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Models.MuxVersionCheckRequest.Get(System.String)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Models.ReceptionAreaVersionCheckRequest.Get(System.String)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Models.ServiceLogoFormatTable.ToStatementParameters~SLDBService.Models.Parameter[]")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Models.ServiceLogoTable.ToStatementParameters~SLDBService.Models.Parameter[]")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ReceptionAreaPolygonAngleDivisor1.#ctor(System.String)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ReceptionAreaPolygonAngleDivisor36.#ctor(System.String)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.ResolveUnknownStationFMPI.Resolve(System.Data.IDbConnection,SLDBService.Models.UnknownStationRequest)~System.Threading.Tasks.Task{SLDBService.Services.UnknownStation.UnknownStationLookupResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.ECC(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.EID(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.ONID(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.SID(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Services.UnknownStation.UnknownStationRequestExtensions.TSID(SLDBService.Models.UnknownStationRequest)~System.String")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.SLDBReset.ConfirmReset(System.String)~System.Threading.Tasks.Task")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.SLDBReset.FinishReset(System.String)~System.Threading.Tasks.Task")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.StatementMetadata.ServiceConfiguration.GetIntValue(System.String)~System.Int32")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.BaseDataVersionCheckResponse.ImageTransactions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.BaseDataVersionCheckResponse.Transactions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.MuxVersionCheckResponse.Transactions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.Preparedstatementvalue.keyvaluelist")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.ReceptionAreaVersionCheckResponse.Transactions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.ServiceLogoTable.stationLogoData")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.SLDBDataSetVersionCheck.required")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.SLDBDataSetVersionCheck.stations")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.SLDBDataSetVersionResponse.OutDatedLinkingIDs")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.SLDBDataSetVersionResponse.PreparedStatementValues")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.SLDBDataSetVersionResponse.UnknownLinkingIDs")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.SLDBDataSetVersionResponse.UpToDateLinkingIDs")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.StationLogoResponse.LogoData")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.Transaction.Parameters")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.UnknownStationResponse.ImageTransactions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.Models.UnknownStationResponse.Transactions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.StatementMetadata.PreparedStatement.ExecutionQueryConditions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.StatementMetadata.PreparedStatement.Parameters")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:SLDBService.StatementMetadata.PreparedStatement.SourceQueryConditions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Controllers.SLDBController.BaseDataVersionCheck(System.String,SLDBService.Models.BaseDataVersionCheckRequest)~System.Threading.Tasks.Task{Microsoft.AspNetCore.Mvc.IActionResult}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2234:Pass system uri objects instead of strings", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.HttpClientExtensions.PostAsJsonAsync``1(System.Net.Http.HttpClient,System.String,``0)~System.Threading.Tasks.Task{System.Net.Http.HttpResponseMessage}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.HttpClientExtensions.PostAsJsonAsync``1(System.Net.Http.HttpClient,System.String,``0)~System.Threading.Tasks.Task{System.Net.Http.HttpResponseMessage}")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "<Pending>", Scope = "member", Target = "~M:SLDBService.Startup.ConfigureServices(Microsoft.Extensions.DependencyInjection.IServiceCollection)~System.IServiceProvider")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Services.UnknownStation.DistanceAtAngle")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "<Pending>", Scope = "type", Target = "~T:SLDBService.Services.UnknownStation.Distances")]```

```csharp
// FILEPATH: ./Program.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Builder;
using MediatR;
using System.Reflection;
using SLDBService;
using Microsoft.Extensions.Logging;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.DependencyInjection;

namespace SLDBService
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var startUp = new Startup(builder.Configuration);
            startUp.ConfigureServices(builder.Services);
            var app = builder.Build();
            startUp.Configure(app, builder.Environment, null);            
            app.Run();
        }
    }
}


```

```csharp
// FILEPATH: ./Handler/VersionCheck/TransactionResult.cs
using SLDBService.Models;
using System.Collections.Generic;

namespace SLDBService.Handler.VersionCheck
{
    public class TransactionResult
    {
        private TransactionResult()
        {
        }

        public IEnumerable<Transaction> Transactions { get; set; }
        public ResultStatus Status { get; set; }

        public static TransactionResult NotFound()
           => new TransactionResult { Transactions = new List<Transaction>(), Status = ResultStatus.NotFound };

        public static TransactionResult NotModified()
            => new TransactionResult { Transactions = new List<Transaction>(), Status = ResultStatus.NotModified };

        public static TransactionResult Success(IEnumerable<Transaction> transactions)
            => new TransactionResult { Transactions = transactions, Status = ResultStatus.Success };
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/IPreparedStatementHandler.cs
using System;
using System.Collections.Generic;

namespace SLDBService.Handler.VersionCheck
{
    /// <summary>
    /// Interface with purpose to improve testability of handlers. 
    /// </summary>
    public interface IPreparedStatementHandler
    {
        /// <summary>
        /// Returns statement ids of statements processed by this handler.
        /// </summary>
        /// <returns></returns>
        IEnumerable<int> GetStatementIds();

        /// <summary>
        /// Returns model type that is used in prepared statement.
        /// </summary>
        Type GetModelType();
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/ImageTransactionResult.cs
using SLDBService.Models;
using System.Collections.Generic;

namespace SLDBService.Handler.VersionCheck
{

    public class ImageTransactionResult
    {
        private ImageTransactionResult()
        {
        }

        public IEnumerable<ImageTransaction> Transactions { get; set; }

        public ResultStatus Status { get; set; }

        public static ImageTransactionResult NotFound()
           => new ImageTransactionResult { Transactions = new List<ImageTransaction>(), Status = ResultStatus.NotFound };

        public static ImageTransactionResult NotModified()
            => new ImageTransactionResult { Transactions = new List<ImageTransaction>(), Status = ResultStatus.NotModified };

        public static ImageTransactionResult Success(IEnumerable<ImageTransaction> imageTransactions)
            => new ImageTransactionResult { Transactions = imageTransactions, Status = ResultStatus.Success };
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/MuxVersionCheckRequestHandler.cs
using MediatR;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Handler.VersionCheck.Mux;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;

namespace SLDBService.Handler.VersionCheck
{
    public class MuxVersionCheckRequestHandler : IRequestHandler<MuxVersionCheckRequest, MuxVersionCheckResponse>
    {
        public IConnectionFactory ConnectionFactory { get; }
        public IPreparedStatementRepository Repository { get; }
        public IExecuteScripts ScriptRunner { get; }
        public TelemetryClient Logger { get; }

        public MuxVersionCheckRequestHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner, TelemetryClient logger)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
            Repository = repository ?? throw new ArgumentNullException(nameof(repository));
            ScriptRunner = scriptRunner ?? throw new ArgumentNullException(nameof(scriptRunner));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<MuxVersionCheckResponse> Handle(MuxVersionCheckRequest request, CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("MuxVersionCheckRequestHandler.Handle"))
            {
                var taskHandleMuxDomain = HandleMuxDomainAsync(request,cancellationToken);
                var transactions = await taskHandleMuxDomain.ConfigureAwait(false);

                var result = new MuxVersionCheckResponse
                {
                    HandleNumber = request.HandleNumber,
                    Transactions = transactions.Transactions.ToArray()
                };

                // write a log entry, if there is not a single transaction returned
                if (result.Transactions.Length == 0)
                {
                    Logger.TrackTrace("Request yielded no transaction to return.", Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Warning);
                }

                return result;
            }

        }

        private Task<bool> CheckMuxIdExists(int linkingId, int muxId)
        {
            using (var scope = Tracer.Instance.StartActive("MuxVersionCheckRequestHandler.CheckMuxIdExists"))
            {
                var validator = new MuxIdValidator(ConnectionFactory);

                return validator.ExistsAsync(linkingId, muxId);
            }
        }

        public Task<TransactionResult> HandleMuxDomainAsync(MuxVersionCheckRequest request, CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("MuxVersionCheckRequestHandler.HandleMuxDomainAsync"))
            {
                var handler = new MuxDomainHandler(ConnectionFactory, Repository, ScriptRunner);

                return handler.ExecuteAsync(request, request.DbModelVersion,cancellationToken);
            }
        }
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/LinkingIdValidator.cs
using Dapper;
using SLDBService.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace SLDBService.Handler.VersionCheck
{
    // TODO: OPTIMIZE: Hold a HashSet<int> with all LinkingIds in memory!

    /// <summary>
    /// Checks whether a given LinkingId exists in the database.
    /// </summary>
    /// <remarks>
    /// At the moment this implementation queries the database for the linking id. There is good potential
    /// for optimizing this.
    /// </remarks>
    public class LinkingIdValidator
    {
        private const string sqlQuery = "SELECT COUNT(*) FROM serviceDataTable WHERE linkingId = (@LinkingId)";
        
        public IConnectionFactory ConnectionFactory { get; }

        private static HashSet<int> linkingIdSet = new HashSet<int>();

        public LinkingIdValidator(IConnectionFactory connectionFactory)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        }

        /// <summary>
        /// Returns an indication whether the given linkingId exists in the database.
        /// </summary>
        /// <param name="linkingId"></param>
        /// <returns></returns>
        public async Task<bool> ExistsAsync(int linkingId)
        {
            if (!linkingIdSet.Contains(linkingId))
            {
                using (var connection = ConnectionFactory.Create())
                {
                    var count = await connection.ExecuteScalarAsync<int>(sqlQuery, new { linkingId }).ConfigureAwait(false);

                    if (count == 1)
                    {
                        linkingIdSet.Add(linkingId);
                        return true;
                    }
                    return false;
                }
            }
            return true;
        }
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/MuxIdValidator.cs
using Dapper;
using SLDBService.Data;
using System;
using System.Threading.Tasks;

namespace SLDBService.Handler.VersionCheck
{
    /// <summary>
    /// Checks whether a given MuxId for given LinkingId exists in the database.
    /// </summary>
    /// <remarks>
    /// At the moment this implementation queries the database for the mux id and linking id. There is good potential
    /// for optimizing this.
    /// </remarks>
    public class MuxIdValidator
    {
        private const string sqlQuery = "SELECT COUNT(*) FROM muxToServiceMappingTable WHERE muxId = (@muxId)";

        public IConnectionFactory ConnectionFactory { get; }

        public MuxIdValidator(IConnectionFactory connectionFactory)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        }

        /// <summary>
        /// Returns an indication whether the given muxId / linkindId combination exists in the database.
        /// </summary>
        /// <returns></returns>
        public async Task<bool> ExistsAsync(int linkingId, int muxId)
        {
            using (var connection = ConnectionFactory.Create())
            {
                var count = await connection.ExecuteScalarAsync<int>(sqlQuery, new { muxId, linkingId }).ConfigureAwait(false);

                return count > 0;
            }
        }
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/DomainHandler.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SLDBService.Handler.VersionCheck
{
    public abstract class DomainHandler<TRequest>
        where TRequest : IHttpRequestData
    {
        private class DistinctExecutionQueryComparer : IEqualityComparer<PreparedStatement>
        {
            public bool Equals(PreparedStatement x, PreparedStatement y)
            {
                return x?.ExecutionQuery == y?.ExecutionQuery;
            }

            public int GetHashCode(PreparedStatement obj)
            {
                return obj?.ExecutionQuery?.GetHashCode() ?? 0;
            }
        }

        public IConnectionFactory ConnectionFactory { get; }
        public IPreparedStatementRepository Repository { get; }
        public IExecuteScripts ScriptRunner { get; }

        protected DomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
            Repository = repository ?? throw new ArgumentNullException(nameof(repository));
            ScriptRunner = scriptRunner ?? throw new ArgumentNullException(nameof(scriptRunner));
        }

        protected abstract DataDomain Domain { get; }

        public virtual async Task<TransactionResult> ExecuteAsync(TRequest request, Version dbModelVersion,CancellationToken cancellationToken)
        {
            //using (var connection = ConnectionFactory.Create())
            {
                var statements = await Repository.FindForDomainAndVersion(Domain, dbModelVersion).ConfigureAwait(false) ?? Enumerable.Empty<PreparedStatement>();
                var context = new StatementContext(request, ScriptRunner);

                return await GetTransactions(statements, context, dbModelVersion,cancellationToken).ConfigureAwait(false);
            }
        }

        protected async Task<TransactionResult> GetTransactions(IEnumerable<PreparedStatement> statements, StatementContext context, Version dbModelVersion,CancellationToken cancellationToken)
        {
            var transactions = new List<Transaction>();
            Dictionary<string, bool> executionQueryMap;

            executionQueryMap = await CreateExecutionQueryMap(statements, context,cancellationToken).ConfigureAwait(false);

            foreach (var statement in statements)
            {
                // check if statement transactions need to be returned
                if (statement.ExecutionQuery == null || executionQueryMap[statement.ExecutionQuery])
                {
                    using (var con = ConnectionFactory.Create())
                    {
                        var txs = await statement.CreateTransactions(con, context,cancellationToken).ConfigureAwait(false);

                        transactions.AddRange(txs);
                    }
                }

            }

            return TransactionResult.Success(transactions.OrderBy(x => x.StatementId));
        }

        /// <summary>
        /// Builds a dictionary containing distinct <see cref="PreparedStatement.ExecutionQuery"/> values and the result of those. 
        /// A result of true means the <see cref="PreparedStatement.ExecutionQuery"/> returned at least one result and the prepared statement
        /// needs to be executed.
        /// </summary>
        /// <param name="statements"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        private async Task<Dictionary<string, bool>> CreateExecutionQueryMap(IEnumerable<PreparedStatement> statements, StatementContext context, CancellationToken cancellationToken)
        {
            var filteredStatements = statements.Where(x => x.ExecutionQuery != null).Distinct(new DistinctExecutionQueryComparer());

            Dictionary<string, bool> map = new Dictionary<string, bool>();
            foreach (var statement in filteredStatements)
            {
                using (var con = ConnectionFactory.Create())
                {
                    var result = await statement.GetExecutionQueryResult(con, context, cancellationToken).ConfigureAwait(false);
                    //var result = con.Query(statement.ExecutionQuery, parameters);
                    _ = result.Count();
                    map.Add(statement.ExecutionQuery, result?.Any() ?? false);
                }
            }

            return map;
        }
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/ReceptionAreaVersionCheckRequestHandler.cs
using MediatR;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Handler.VersionCheck.ReceptionArea;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SLDBService.Handler.VersionCheck
{
    public class ReceptionAreaVersionCheckRequestHandler : IRequestHandler<ReceptionAreaVersionCheckRequest, ReceptionAreaVersionCheckResponse>
    {
        public IConnectionFactory ConnectionFactory { get; }
        public IPreparedStatementRepository Repository { get; }
        public IExecuteScripts ScriptRunner { get; }
        public TelemetryClient Logger { get; }

        public ReceptionAreaVersionCheckRequestHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner, TelemetryClient logger)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
            Repository = repository ?? throw new ArgumentNullException(nameof(repository));
            ScriptRunner = scriptRunner ?? throw new ArgumentNullException(nameof(scriptRunner));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }


        public async Task<ReceptionAreaVersionCheckResponse> Handle(ReceptionAreaVersionCheckRequest request, CancellationToken cancellationToken)
        {
            var taskHandleReceptionAreaDomain = HandleReceptionAreaDomainAsync(request, cancellationToken);
            var transactions = await taskHandleReceptionAreaDomain.ConfigureAwait(false);

            var result =  new ReceptionAreaVersionCheckResponse
            {
                HandleNumber = request.HandleNumber,
                Transactions = transactions.Transactions.ToArray()
            };

            // write a log entry, if there is not a single transaction returned
            if (result.Transactions.Length == 0)
            {
                Logger.TrackTrace("Request yielded no transaction to return.", Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Warning);
            }

            return result;
        }
        
        public Task<TransactionResult> HandleReceptionAreaDomainAsync(ReceptionAreaVersionCheckRequest request, CancellationToken cancellationToken)
        {
            var handler = new ReceptionAreaDomainHandler(ConnectionFactory, Repository, ScriptRunner);

            return handler.ExecuteAsync(request, request.DbModelVersion, cancellationToken);
        }
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/BaseDataVersionCheckRequestHandler.cs
using Dapper;
using MediatR;
using Microsoft.ApplicationInsights;
using Newtonsoft.Json;
using SLDBService.Data;
using SLDBService.Handler.VersionCheck.BaseData;
using SLDBService.Handler.VersionCheck.Genre;
using SLDBService.Handler.VersionCheck.Logo;
using SLDBService.Handler.VersionCheck.Metadata;
using SLDBService.Handler.VersionCheck.Phonetic;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SLDBService.Handler.VersionCheck
{
    public class BaseDataVersionCheckRequestHandler : IRequestHandler<BaseDataVersionCheckRequest, BaseDataVersionCheckResponse>
    {
        public IConnectionFactory ConnectionFactory { get; }
        public IPreparedStatementRepository Repository { get; }
        public IExecuteScripts ScriptRunner { get; }
        public TelemetryClient Logger { get; }

        public IProvideRequestHeaders RequestHeadersProvider { get; }

        //private ConnectionMultiplexer _redisConnection;

        private static ConcurrentDictionary<String, double> _lastUpdated = new ConcurrentDictionary<string, double>(StringComparer.Ordinal);
        private static string _baseTransactionResult = null;
        //private static string _emptyTransactions = null;

        //private static Dictionary<int, int> _regionIdBasVersionMap = null;

        
        private int _timeoutInMinutes = SLDBConfiguration.TIMEOUT_IN_MINUTES;



        public BaseDataVersionCheckRequestHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner, TelemetryClient logger, IProvideRequestHeaders requestHeadersProvider)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
            Repository = repository ?? throw new ArgumentNullException(nameof(repository));
            ScriptRunner = scriptRunner ?? throw new ArgumentNullException(nameof(scriptRunner));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            RequestHeadersProvider = requestHeadersProvider ?? throw new ArgumentNullException(nameof(requestHeadersProvider));
            //_redisConnection = redisConnection ?? throw new ArgumentNullException(nameof(_redisConnection));
            init();


        }

        private void init()
        {
            /*if (_regionIdBasVersionMap == null)
            {
                lock (_initSyncObj)
                {
                    if (_regionIdBasVersionMap == null)
                    {
                        //Logger.TrackTrace("Initializing version region map");

                        _regionIdBasVersionMap = new Dictionary<int, int>();
                        const string sql = "select regionId,versionBAS from productDbTable";
                        using (var con = ConnectionFactory.Create())
                        {
                            var map = con.Query<ProductDbTable>(sql);

                            foreach (var row in map)
                            {
                                _regionIdBasVersionMap[row.regionId] = row.versionBAS;
                            }

                        }
                        _emptyTransactions = JsonConvert.SerializeObject(TransactionResult.NotModified().Transactions, Formatting.None);
                    }
                }
            }*/

        }

        public async Task<BaseDataVersionCheckResponse> Handle(BaseDataVersionCheckRequest request, CancellationToken cancellationToken)
        {

            var sessionId = $"{SLDBConfiguration.SLOT_NAME}-{RequestHeadersProvider.GetSessionId()}";
            bool skipBASDomain = request.SkipBASDomain;
            if (skipBASDomain == false)
            {
                //check key exists locally
                var currentTimeInMinutes = DateTime.Now.TimeOfDay.TotalMinutes;
                    
                if (_lastUpdated.ContainsKey(sessionId))
                {
                    _lastUpdated.TryGetValue(sessionId, out double lastUpdated);
                    if (currentTimeInMinutes - lastUpdated < _timeoutInMinutes)
                    {
                        
                        skipBASDomain = true;
                    }
                    else{
                        
                        //_lastUpdated.TryRemove(sessionId,out _);
                        _lastUpdated.TryUpdate(sessionId, currentTimeInMinutes,lastUpdated);
                        
                    }

                }
                else{
                    _lastUpdated.TryAdd(sessionId, currentTimeInMinutes);
                }
                
            }

            var taskHandleBaseData =
                skipBASDomain
                ? Task.FromResult(TransactionResult.NotModified())
                : HandleBaseDataDomainAsync(request,cancellationToken);

            var taskHandleLogo = HandleLogoDomainAsync(request,cancellationToken);
            var taskHandleGenre = 
                SLDBConfiguration.SkipGenDomain? Task.FromResult(TransactionResult.NotModified())
                : HandleGenreDomainAsync(request,cancellationToken);
            var taskHandlePhonetic = HandlePhoneticDomainAsync(request,cancellationToken);
            var taskHandleMetadata = HandleMetadataDomainAsync(request,cancellationToken);

           await Task.WhenAll
            (
                taskHandleLogo,
                taskHandleBaseData,
                taskHandleGenre,
                taskHandlePhonetic,
                taskHandleMetadata
            ).ConfigureAwait(false);


            var baseResult = taskHandleBaseData.Result;
            var genreResult = taskHandleGenre.Result;
            var phoneticResult = taskHandlePhonetic.Result;
            var metadataResult = taskHandleMetadata.Result;
            var logoResult = taskHandleLogo.Result;

            var transactions =
                baseResult.Transactions
                .Concat(genreResult.Transactions)
                .Concat(phoneticResult.Transactions)
                .Concat(metadataResult.Transactions)
                .ToArray();

            var result = new BaseDataVersionCheckResponse
            {
                HandleNumber = request.HandleNumber,
                LinkingId = request.LinkingId,
                ImageTransactions = logoResult.Transactions.ToArray(),
                Transactions = transactions
            };

            // write a log entry, if there is not a single transaction returned
            if (result.Transactions.Length + result.ImageTransactions.Length == 0)
            {
                Logger.TrackTrace("Request yielded no transaction to return.", Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Warning);
                result.Status = ResultStatus.NotFound;
            }

            return result;
        }

        public Task<ImageTransactionResult> HandleLogoDomainAsync(BaseDataVersionCheckRequest request,CancellationToken cancellationToken)
        {
            var handler = new LogoDomainHandler(ConnectionFactory, Repository, ScriptRunner);

            return handler.ExecuteAsync(request, request.DbModelVersion,cancellationToken);
        }

        public Task<TransactionResult> HandleBaseDataDomainAsync(BaseDataVersionCheckRequest request,CancellationToken cancellationToken)
        {
            var handler = new BaseDataDomainHandler(ConnectionFactory, Repository, ScriptRunner);
            return handler.ExecuteAsync(request, request.DbModelVersion,cancellationToken);
        }

        public Task<TransactionResult> HandleGenreDomainAsync(BaseDataVersionCheckRequest request,CancellationToken cancellationToken)
        {
            var handler = new GenreDomainHandler(ConnectionFactory, Repository, ScriptRunner);

            return handler.ExecuteAsync(request, request.DbModelVersion,cancellationToken);
        }

        public Task<TransactionResult> HandlePhoneticDomainAsync(BaseDataVersionCheckRequest request,CancellationToken cancellationToken)
        {
            var handler = new PhoneticDomainHandler(ConnectionFactory, Repository, ScriptRunner);

            return handler.ExecuteAsync(request, request.DbModelVersion,cancellationToken);
        }

        public Task<TransactionResult> HandleMetadataDomainAsync(BaseDataVersionCheckRequest request,CancellationToken cancellationToken)
        {
            var handler = new MetadataDomainHandler(ConnectionFactory, Repository, ScriptRunner);

            return handler.ExecuteAsync(request, request.DbModelVersion,cancellationToken);
        }
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/BaseData/BaseDataDomainHandler.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace SLDBService.Handler.VersionCheck.BaseData
{
    public class BaseDataDomainHandler : DomainHandler<BaseDataVersionCheckRequest>
    {
        public BaseDataDomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
            : base(connectionFactory, repository, scriptRunner)
        {
        }

        protected override DataDomain Domain => DataDomain.BAS;
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/Mux/MuxDomainHandler.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace SLDBService.Handler.VersionCheck.Mux
{
    public class MuxDomainHandler : DomainHandler<MuxVersionCheckRequest>
    {
        public MuxDomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
            : base(connectionFactory, repository, scriptRunner)
        {
        }

        protected override DataDomain Domain => DataDomain.MUX;
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/Genre/GenreDomainHandler.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace SLDBService.Handler.VersionCheck.Genre
{
    public class GenreDomainHandler : DomainHandler<BaseDataVersionCheckRequest>
    {
        public GenreDomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
            : base(connectionFactory, repository, scriptRunner)
        {
        }

        protected override DataDomain Domain => DataDomain.GEN;
        
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/Logo/LogoDomainHandler.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace SLDBService.Handler.VersionCheck.Logo
{
    public class LogoDomainHandler
    {

        public class InnerLogoDomainHandler : DomainHandler<BaseDataVersionCheckRequest>

        {
            public InnerLogoDomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
                : base(connectionFactory, repository, scriptRunner)
            {
            }

            protected override DataDomain Domain => DataDomain.LOG;
        }

        private const string sqlQueryLogoData = "SELECT stationLogoFormatId, stationLogoData FROM serviceLogoTable WHERE StationLogoId = (SELECT stationLogoId FROM serviceDataTable WHERE linkingId = @LinkingId)";

        public InnerLogoDomainHandler InnerHandler { get; }

        public LogoDomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
        {
            InnerHandler = new InnerLogoDomainHandler(connectionFactory, repository, scriptRunner);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>")]
        public async Task<ImageTransactionResult> ExecuteAsync(BaseDataVersionCheckRequest request, Version dbModelVersion,CancellationToken cancellationToken)
        {
            var txs = await InnerHandler.ExecuteAsync(request, dbModelVersion,cancellationToken).ConfigureAwait(false);
            if (!txs.Transactions.Any())
            {
                return ImageTransactionResult.NotModified();
            }
            else
            {
                using (var conn = InnerHandler.ConnectionFactory.Create())
                {
                    var command = new CommandDefinition(sqlQueryLogoData, new { request.LinkingId }, cancellationToken: cancellationToken);

                    var logoData = await conn.QueryAsync(command).ConfigureAwait(false);


                    return ImageTransactionResult.Success(
                            txs.Transactions.Select(tx => new ImageTransaction
                            {
                                StatementId = tx.StatementId,
                                Parameters = tx.Parameters,
                                ImageLink = request.CreateImageLink(
                                    request.LinkingId,
                                    Convert.ToInt32(tx.Parameters.Single(x => x.Placeholder == "StationLogoId").PlaceholderValue),
                                    Convert.ToInt32(tx.Parameters.Single(x => x.Placeholder == "versionLOG").PlaceholderValue),
                                    Convert.ToInt32(tx.Parameters.Single(x => x.Placeholder == "stationLogoFormatId").PlaceholderValue)),
                                ImageMD5Base64 = ImageMD5Base64(
                                    logoData
                                        .Single(x => x.stationLogoFormatId == Convert.ToInt32(tx.Parameters.Single(y => y.Placeholder == "stationLogoFormatId").PlaceholderValue))
                                        .stationLogoData)
                            }));
                }
            }
        }

        private string ImageMD5Base64(byte[] logoImage)
        {


            return Convert.ToBase64String(System.Security.Cryptography.MD5.Create().ComputeHash(logoImage));


        }
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/ReceptionArea/ReceptionAreaDomainHandler.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace SLDBService.Handler.VersionCheck.ReceptionArea
{
    public class ReceptionAreaDomainHandler : DomainHandler<ReceptionAreaVersionCheckRequest>
    {
        public ReceptionAreaDomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
            : base(connectionFactory, repository, scriptRunner)
        {
        }

        protected override DataDomain Domain => DataDomain.REC;
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/Metadata/MetadataDomainHandler.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Data;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.Handler.VersionCheck.Metadata
{
    public class MetadataDomainHandler : DomainHandler<BaseDataVersionCheckRequest>
    {
        public MetadataDomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
            : base(connectionFactory, repository, scriptRunner)
        {
        }

        protected override DataDomain Domain => DataDomain.MET;
    }
}```

```csharp
// FILEPATH: ./Handler/VersionCheck/Phonetic/PhoneticDomainHandler.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.StatementMetadata;
using System;
using System.Data;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.Handler.VersionCheck.Phonetic
{
    public class PhoneticDomainHandler : DomainHandler<BaseDataVersionCheckRequest>
    {
        public PhoneticDomainHandler(IConnectionFactory connectionFactory, IPreparedStatementRepository repository, IExecuteScripts scriptRunner)
            : base(connectionFactory, repository, scriptRunner)
        {
        }

        protected override DataDomain Domain => DataDomain.PHO;
    }

}```

```csharp
// FILEPATH: ./Handler/Reset/ResetSldbRequestHandler.cs
using MediatR;
using SLDBService.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Shared;
using Microsoft.WindowsAzure.Storage.Core;
using Microsoft.WindowsAzure.Storage.Table;

namespace SLDBService.Handler.Reset
{
    public class ResetSldbRequestHandler : IRequestHandler<ResetSldbRequest, ResetSldbResponse>
    {
        public ISLDBReset ResetService { get; }

        public ResetSldbRequestHandler(ISLDBReset resetService)
        {
            ResetService = resetService ?? throw new ArgumentNullException(nameof(resetService));
        }

        public async Task<ResetSldbResponse> Handle(ResetSldbRequest request, CancellationToken cancellationToken)
        {
            try
            {
                if (request.ConfirmsReset)
                {
                    if (await ResetService.ShouldReset().ConfigureAwait(false))
                    {
                        await ResetService.ConfirmReset(request.version).ConfigureAwait(false);
                        return ResetSldbResponse.Success();
                    }
                    else
                    {
                        return ResetSldbResponse.NotAllowed();
                    }
                }
                else if (request.FinishesReset)
                {
                    if (await ResetService.ShouldReset().ConfigureAwait(false))
                    {
                        await ResetService.FinishReset(request.version).ConfigureAwait(false);
                        return ResetSldbResponse.Success();
                    }
                    else
                    {
                        return ResetSldbResponse.NotAllowed();
                    }
                }
                else
                {
                    return ResetSldbResponse.NotAllowed();  // in case of invalid request contents, do not allow sldb reset
                }
            }
            catch
            {
                return ResetSldbResponse.NotAllowed();  // in case of error, do not allow sldb reset
            }
        }
    }
}```

```csharp
// FILEPATH: ./Handler/Logo/StationLogoRequestHandler.cs
using Dapper;
using MediatR;
using SLDBService.Data;
using SLDBService.Models;
using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace SLDBService.Handler.Logo
{
    /// <summary>
    /// Handler for <see cref="StationLogoRequest"/>
    /// </summary>
    public class StationLogoRequestHandler : IRequestHandler<StationLogoRequest, StationLogoResponse>
    {
        private const string sqlQueryLogoId = "SELECT stationLogoId FROM serviceDataTable WHERE linkingId = (@LinkingId)";

        private const string sqlQueryLogoData =
            "SELECT stationLogoData FROM serviceLogoTable " +
            "WHERE stationLogoFormatId = (@Format) AND versionLOG = (@Version) AND StationLogoId = (@LogoId)";

        public IConnectionFactory ConnectionFactory { get; }

        public StationLogoRequestHandler(IConnectionFactory connectionFactory)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        }

        public async Task<StationLogoResponse> Handle(StationLogoRequest request, CancellationToken cancellationToken)
        {
            using (var connection = ConnectionFactory.Create())
            {
                var logoId = await connection.QueryFirstOrDefaultAsync<int?>(sqlQueryLogoId, request).ConfigureAwait(false);
                if (logoId != request.LogoId)
                {
                    return StationLogoResponse.NotFound;
                }

                var logoData = await connection.QueryFirstOrDefaultAsync<byte[]>(sqlQueryLogoData, request).ConfigureAwait(false);

                if (logoData != null)
                {
                    return new StationLogoResponse(logoData);
                }
                else
                {
                    return StationLogoResponse.NotFound;
                }
            }
        }
    }
}```

```csharp
// FILEPATH: ./Handler/UnknownStation/UnknownStationHandlerConfiguration.cs
namespace SLDBService.Handler.UnknownStation
{
    public class UnknownStationHandlerConfiguration
    {
        public string StorageConnection { get; }

        public UnknownStationHandlerConfiguration(string storageConnection)
        {
            StorageConnection = storageConnection;
        }
    }
}```

```csharp
// FILEPATH: ./Handler/UnknownStation/UnknownStationRequestHandler.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using MediatR;
using Microsoft.ApplicationInsights;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using Newtonsoft.Json;
using SLDBService.Data;
using SLDBService.Models;
using SLDBService.Services.UnknownStation;
using System.Collections.Concurrent;
using SLDBService.UnknownStation;
using SLDBService.StatementMetadata;
using System.Linq;

namespace SLDBService.Handler.UnknownStation
{
    public class UnknownStationRequestHandler : IRequestHandler<UnknownStationRequest, UnknownStationResponse>
    {
        public UnknownStationHandlerConfiguration Configuration { get; }
        public IEnumerable<IResolveUnknownStation> Resolvers { get; }
        public IMediator Mediator { get; }
        public IFindLogoId LogoIdFinder { get; }
        public TelemetryClient Logger { get; }

        public IConnectionFactory ConnectionFactory { get; }

        public IUnknownStationsStorage Storage { get; }
        public IPreparedStatementRepository Repository { get; }

        IExecuteScripts ScriptRunner;

        
        static ConcurrentQueue<UnknownStationTableEntity> queue = new ConcurrentQueue<UnknownStationTableEntity>();

        public UnknownStationRequestHandler(UnknownStationHandlerConfiguration configuration,
            IEnumerable<IResolveUnknownStation> resolvers, IMediator mediator, IFindLogoId logoIdFinder,
            TelemetryClient logger, IConnectionFactory connectionFactory, IUnknownStationsStorage storage, IPreparedStatementRepository repository,IExecuteScripts scriptRunner)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            Resolvers = resolvers ?? throw new ArgumentNullException(nameof(resolvers));
            Mediator = mediator ?? throw new ArgumentNullException(nameof(mediator));
            LogoIdFinder = logoIdFinder ?? throw new ArgumentNullException(nameof(logoIdFinder));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
            Storage = storage ?? throw new ArgumentNullException(nameof(storage));
            Repository = repository ?? throw new ArgumentNullException(nameof(repository));
            ScriptRunner = scriptRunner ?? throw new ArgumentNullException(nameof(scriptRunner));
        }

        public async Task<UnknownStationResponse> Handle(UnknownStationRequest request,
            CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("UnknownStationRequestHandler.Handle"))
            {
                var resolver = ChooseResolver(request); //request will never be null.

                if (resolver == null)
                {
                    await Storage.StoreRequest(request,
                            "No unknown station resolver for broadcasting standard defined in this request.",cancellationToken)
                        .ConfigureAwait(false);

                    return UnknownStationResponse.NotFound();
                }

                var result = await resolver.Resolve(request,cancellationToken).ConfigureAwait(false);

                if (result.Reason != null)
                {
                    // store all requests that have a reason associated, regardless of success or failure
                    await Storage.StoreRequest(request, result.Reason,cancellationToken).ConfigureAwait(false);
                }

                if (!result.Success)
                {
                    if (result.Reason == null)
                    {
                        await Storage.StoreRequest(request, "Could not resolve unknown station.",cancellationToken).ConfigureAwait(false);
                    }

                    return UnknownStationResponse.NotFound();
                }

                // Create transactions from result
                var muxDomainTask =  GetTransactionsMUX(request, result, cancellationToken);
                var recDomainTask =  GetTransactionsREC(request, result, cancellationToken);
                var logoIdTask =  LogoIdFinder.Find(result.LinkingId.Value, cancellationToken);
                var ttlTask = GetTrasactionTTL(request, cancellationToken);
                await Task.WhenAll(
                    muxDomainTask,
                    recDomainTask,
                    logoIdTask,
                    ttlTask)
                    .ConfigureAwait(false);
                var muxDomain = muxDomainTask.Result;
                var recDomain = recDomainTask.Result;
                var logoId = logoIdTask.Result;
                var ttl = ttlTask.Result;


                // lookup logoId for bas domain transactions
                var basDomain = await GetTransactionsMET_LOG_PHO_GEN(request, result, logoId, cancellationToken).ConfigureAwait(false);

                return new UnknownStationResponse
                {
                    HandleNumber = request.HandleNumber,
                    ImageTransactions = basDomain.ImageTransactions,
                    LinkingId = result.LinkingId.Value,
                    LogoId = logoId,
                    Status = ResultStatus.Success,
                    TempOrLinkingId = request.TempOrLinkingId,
                    Transactions = basDomain.Transactions.Concat(muxDomain).Concat(recDomain)
                        .OrderBy(x => x.StatementId).ToArray()
                };
            }
        }

        private IResolveUnknownStation ChooseResolver(UnknownStationRequest request)
        {
            var broadcastingId = request.BroadcastStandard;

            return Resolvers.FirstOrDefault(x => x.BroadcastingStandardNameId == broadcastingId);
        }

        private async Task<Transaction[]> GetTransactionsREC(UnknownStationRequest request,
            UnknownStationLookupResult lookupResult, CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("UnknownStationRequestHandler.GetTransactionsREC"))
            {
                var req = new ReceptionAreaVersionCheckRequest
                {
                    DbModelVersion = request.DBModelVersion(),
                    FrequencyId = lookupResult.FrequencyId.Value,
                    HandleNumber = 0,
                    MuxId = lookupResult.MuxId.Value,
                    ReceptionAreaId = lookupResult.ReceptionAreaId.Value,
                    TransmitterId = lookupResult.TransmitterId.Value,
                    VersionREC = 0 // this will ensure we actually get results back
                };
                ReceptionAreaVersionCheckResponse result;
                /*var status = false;
                using (var conn = ConnectionFactory.Create())
                {
                    (status, result) = await conn.GetFromCachedResultsNonSql<ReceptionAreaVersionCheckResponse>(req)
                        .ConfigureAwait(false);
                    if (!status)
                    {
                        result = await Mediator.Send(req).ConfigureAwait(false);
                        await conn.StoreCachedResultsNonSql(req, result).ConfigureAwait(false);
                    }
                }*/
                result = await Mediator.Send(req,cancellationToken).ConfigureAwait(false);
                return result.Transactions;
            }
        }

        private async Task<Transaction[]> GetTransactionsMUX(UnknownStationRequest request,
            UnknownStationLookupResult lookupResult, CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("UnknownStationRequestHandler.GetTransactionsMUX"))
            {
                var req = new MuxVersionCheckRequest
                {
                    DbModelVersion = request.DBModelVersion(),
                    HandleNumber = 0,
                    MuxId = lookupResult.MuxId.Value,
                    LinkingId = lookupResult.LinkingId.Value,
                    VersionMUX = 0 // this will ensure we actually get results back
                };
                MuxVersionCheckResponse result;
                /*var status = false;
                using (var conn = ConnectionFactory.Create())
                {
                    (status, result) = await conn.GetFromCachedResultsNonSql<MuxVersionCheckResponse>(req)
                        .ConfigureAwait(false);
                    if (!status)
                    {
                        result = await Mediator.Send(req).ConfigureAwait(false);
                        await conn.StoreCachedResultsNonSql(req, result).ConfigureAwait(false);
                    }
                }*/

                result = await Mediator.Send(req, cancellationToken).ConfigureAwait(false);

                return result.Transactions;
            }
        }

        private async Task<Transaction[]> GetTrasactionTTL(UnknownStationRequest request, CancellationToken cancellationToken){
            var _ttlStatement = (await Repository.FindAll().ConfigureAwait(false)).Where(x => x.SeqNr == 740).First();
            _ttlStatement.ExecutionQuery = @"SELECt 1";//Override the statement to force generate a ttl transaction
            var context = new StatementContext(request, ScriptRunner);
            var _ttlTransactions = await _ttlStatement.CreateTransactions(ConnectionFactory.Create(), context, CancellationToken.None).ConfigureAwait(false);
            return _ttlTransactions.ToArray();
        }

        private async Task<BaseDataVersionCheckResponse> GetTransactionsMET_LOG_PHO_GEN(UnknownStationRequest request,
            UnknownStationLookupResult lookupResult, int logoId, CancellationToken cancellationToken)
        {
            using (var scope =
                   Tracer.Instance.StartActive("UnknownStationRequestHandler.GetTransactionsMET_LOG_PHO_GEN"))
            {
                BaseDataVersionCheckRequest req = new BaseDataVersionCheckRequest
                {
                    DbModelVersion = request.DBModelVersion(),
                    HandleNumber = 0,
                    LinkingId = lookupResult.LinkingId.Value,
                    SkipBASDomain = true,
                    LogoId = logoId,
                    VersionBAS = 0, // doesn't matter, since SkipBASDomain == true
                    VersionGEN = 0,
                    VersionLOG = 0,
                    VersionMET = 0,
                    VersionPHO = 0,
                    CreateImageLink = request.CreateImageLink
                };
                BaseDataVersionCheckResponse result;
                /*var status = false;
                using (var conn = ConnectionFactory.Create())
                {
                    (status, result) = await conn.GetFromCachedResultsNonSql<BaseDataVersionCheckResponse>(req)
                        .ConfigureAwait(false);
                    if (!status)
                    {
                        result = await Mediator.Send(req).ConfigureAwait(false);
                        await conn.StoreCachedResultsNonSql(req, result).ConfigureAwait(false);
                    }
                }*/
                result = await Mediator.Send(req,cancellationToken).ConfigureAwait(false);

                return result;
            }
        }
        //Extract the StoreRequest to another class named UnknowStationsStorage

       
    }
}```

```csharp
// FILEPATH: ./Handler/UnknownStation/UnknowStationStorage.cs
using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using Newtonsoft.Json;
using SLDBService.Handler.UnknownStation;
using SLDBService.Models;

namespace SLDBService.UnknownStation
{
    public class UnknownStationsStorage : IUnknownStationsStorage
    {
        private class TableKeys
        {
            public string PartitionKey { get; set; }
            public string RowKey { get; set; }
        }
        static ConcurrentQueue<UnknownStationTableEntity> queue = new ConcurrentQueue<UnknownStationTableEntity>();
        public UnknownStationHandlerConfiguration Configuration { get; }
        static int counter = 0;
        public TelemetryClient Logger { get; }
        public UnknownStationsStorage(UnknownStationHandlerConfiguration configuration, TelemetryClient logger)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<int> StoreRequest(UnknownStationRequest request, string reason, CancellationToken cancellationToken)
        {
            int count = 1;
            using (var scope = Tracer.Instance.StartActive("UnknownStationRequestHandler.StoreRequest"))
            {

                try
                {
                    var key = CreateKey();
                    if (queue.Count > SLDBConfiguration.UnknownStationsBatchSize)
                    {

                        var account = CloudStorageAccount.Parse(Configuration.StorageConnection);
                        var client = account.CreateCloudTableClient();

                        var table = client.GetTableReference(
                            $"unknownstations{DateTime.UtcNow.ToString("yyyyMMdd", CultureInfo.InvariantCulture)}");

                        await table.CreateIfNotExistsAsync().ConfigureAwait(false);

                        UnknownStationTableEntity entityFromQueue;


                        TableBatchOperation batchOperation = new TableBatchOperation();

                        while (queue.TryDequeue(out entityFromQueue) && batchOperation.Count < SLDBConfiguration.UnknownStationsBatchSize)//Get the UnknownStationsBatchSize items and store
                        {
                            entityFromQueue.PartitionKey = key.PartitionKey;//Reset the partition key such that all the entities are stored in the same partition and avoid exception during batch operation
                            batchOperation.InsertOrReplace(entityFromQueue);
                        }
                        if (batchOperation.Count > 0)
                        {

                            var res = await table.ExecuteBatchAsync(batchOperation).ConfigureAwait(false);
                            count = res.Count;

                        }

                    }
                    else
                    {
                        //JsonConvert.SerializeObject with no new lines

                        var rawJson = JsonConvert.SerializeObject(request, Formatting.None);
                       
                        var entity = new UnknownStationTableEntity(key.PartitionKey, key.RowKey)
                        {
                            RawJson = rawJson,
                            /*Reason = reason,
                            BER = request.BER,
                            BroadcastStandard = request.BroadcastStandard,
                            CoChannel = request.CoChannel,
                            dBModelSubVersion = request.dBModelSubVersion,
                            dBModelVersion = request.dBModelVersion,
                            dBSubVersion = request.dBSubVersion,
                            dBVersion = request.dBVersion,
                            ECC = request.ECC,
                            EnsBouqTSId = request.EnsBouqTSId,
                            Frequency = request.Frequency,
                            HandleNumber = request.HandleNumber,
                            HUQLevel = request.HUQLevel,
                            Intermod = request.Intermod,
                            Kbps = request.Kbps,
                            LatRound = request.LatRound,
                            LongRound = request.LongRound,
                            ONID = request.ONID,
                            OTALogo = request.OTALogo,
                            OTALogoTransaprency = request.OTALogoTransaprency,
                            OTASlideshow = request.OTASlideshow,
                            PTY = request.PTY,
                            RecLevel = request.RecLevel,
                            regionId = request.regionId,
                            RollingPS = request.RollingPS,
                            SNR = request.SNR,
                            StationId = request.StationId,
                            StationIdentificationMatches = request.StationIdentificationMatches,
                            StationNameLong = request.StationNameLong,
                            StationNameShort = request.StationNameShort,
                            Stereo = request.Stereo,
                            SubchannelID = request.SubchannelID,
                            TempOrLinkingId = request.TempOrLinkingId,
                            HUTimestamp = request.TimeStamp,
                            TPFlag = request.TPFlag
                            */
                        };
                        queue.Enqueue(entity);

                    }
                }
                catch (StorageException ex)
                {
                    Logger.TrackException(ex);
                    throw new TaskCanceledException("Failed to store the unknownstation in the table", ex);
                }
                //Logger.TrackTrace("Saved the unknownstation in the table with key",Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Information);
            }
            return count;

        }
        private TableKeys CreateKey()
        {
            var utcNow = DateTimeOffset.UtcNow;
            /*var localCounter = Interlocked.Increment(ref counter);
            Interlocked.CompareExchange(ref counter, 0, 10000);*/
            Guid guid = Guid.NewGuid();
            long numericValue = BitConverter.ToInt64(guid.ToByteArray(), 0);


            return new TableKeys
            {
                PartitionKey = utcNow.ToString("yyyy-MM-dd", DateTimeFormatInfo.CurrentInfo),
                RowKey = utcNow.ToString("HH:mm:ss.ffffff", DateTimeFormatInfo.CurrentInfo) +
                         numericValue.ToString(DateTimeFormatInfo.CurrentInfo).Substring(0, 6)
            };
        }
    }
}```

```csharp
// FILEPATH: ./obj/Debug/net6.0/.NETCoreApp,Version=v6.0.AssemblyAttributes.cs
// <autogenerated />
using System;
using System.Reflection;
[assembly: global::System.Runtime.Versioning.TargetFrameworkAttribute(".NETCoreApp,Version=v6.0", FrameworkDisplayName = ".NET 6.0")]
```

```csharp
// FILEPATH: ./StatementMetadata/ConstantValueConditionParameter.cs
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public class ConstantValueConditionParameter : ConditionParameter
    {
        public string ConstantSqlValue { get; }

        public ConstantValueConditionParameter(string name, string constantSqlValue)
            : base(name)
        {
            ConstantSqlValue = constantSqlValue ?? throw new ArgumentNullException(nameof(constantSqlValue));
        }

        public override Task<string> ProvideSqlValue(StatementContext context)
        {
            return Task.FromResult(ConstantSqlValue);
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/DataDomain.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public enum DataDomain
    {
        BAS,
        GEN,
        LOG,
        MET,
        MUX,
        PHO,
        REC
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/CompiledScriptCache.cs
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public class CompiledScriptCache
    {
        private ConcurrentDictionary<string, ScriptRunner<string>> _compiledScripts = new ConcurrentDictionary<string, ScriptRunner<string>>();

        public CompiledScriptCache()
        {
        }

        public Func<object, Task<string>> GetOrCache(string script)
        {
            var runner = _compiledScripts.GetOrAdd(script, x =>
            {
                var scriptState = CSharpScript.Create<string>(script, options: ScriptOptions.Default.WithImports("System", "System.Math"), globalsType: typeof(IScriptGlobals));

                return scriptState.CreateDelegate();
            });

            return globals => runner(globals);
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/StatementParameter.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public abstract class StatementParameter
    {
        public string Name { get; }
        public StatementParameter(string name)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
        }

        /// <summary>
        /// Provides the value of this parameter as valid sql, i.e. strings are quoted with single-quotes,
        /// numeric values are not quoted, ...
        /// </summary>
        /// <returns></returns>
        public abstract Task<string> ProvideSqlValue(StatementContext context, IDictionary<string, object> tableRow);

        public static StatementParameter CreateFrom(ParameterEntity entity)
        {
            switch (entity.Source.ToLower())
            {
                case "table":
                    return new TableParameter(entity.Name);
                case "constant":
                    return new ConstantValueParameter(entity.Name, entity.Value);
                case "script":
                    return new ScriptParameter(entity.Name, entity.Value);
                case "request":
                    return new RequestParameter(entity.Name);
                default:
                    throw new InvalidOperationException("Cannot create Metadata.Parameter from given Metadata.ParameterEntity.");
            }
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/ServiceConfiguration.cs
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public class ServiceConfiguration : IServiceConfiguration
    {
        public IConfiguration Configuration { get; }

        public ServiceConfiguration(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public int GetIntValue(string setting)
        {
            return Convert.ToInt32(Configuration.GetSection("AppSettings")[setting]);
        }

        public string GetStringValue(string setting)
        {
            return Configuration.GetSection("AppSettings")[setting];
        }
    }
}
```

```csharp
// FILEPATH: ./StatementMetadata/IHttpRequestData.cs
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public interface IHttpRequestData
    {
        string Get(string property);
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/StatementContext.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public class StatementContext
    {
        public IHttpRequestData RequestData { get; }
        public IExecuteScripts ScriptRunner { get; set; }

        public StatementContext(IHttpRequestData requestData, IExecuteScripts scriptRunner)
        {
            RequestData = requestData ?? throw new ArgumentNullException(nameof(requestData));
            ScriptRunner = scriptRunner ?? throw new ArgumentNullException(nameof(scriptRunner));
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/SqlCommands.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public static class SqlCommands
    {
        private class UpdateCommand : SqlCommand
        {
            public UpdateCommand() : base("UPDATE")
            {
            }
        }

        private class InsertCommand : SqlCommand
        {
            public InsertCommand() : base("INSERT")
            {
            }
        }

        private class UpsertCommand : SqlCommand
        {
            public UpsertCommand() : base("UPSERT")
            {
            }
        }

        private class DeleteCommand : SqlCommand
        {
            public DeleteCommand() : base("DELETE")
            {
            }
        }


        public static readonly SqlCommand Update = new UpdateCommand();
        public static readonly SqlCommand Insert = new InsertCommand();
        public static readonly SqlCommand Upsert = new UpsertCommand();
        public static readonly SqlCommand Delete = new DeleteCommand();

        public static SqlCommand Parse(string value)
        {
            switch (value.ToLower())
            {
                case "update":
                    return Update;
                case "insert":
                    return Insert;
                case "upsert":
                    return Upsert;
                case "delete":
                    return Delete;
                default:
                    throw new FormatException($"Unable to parse '{value}' as a SqlCommand.");
            }
        }

    }
}```

```csharp
// FILEPATH: ./StatementMetadata/ConditionParameterEntity.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public class ConditionParameterEntity
    {
        /// <summary>
        /// Name of the parameter in the prepared statement's condition
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Source of the value of the parameter represented as string 
        /// (e.g. <see cref="RequestConditionParameter"/>, <see cref="ConstantValueConditionParameter"/>, <see cref="ScriptConditionParameter"/>)
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// Value of the parameter; in case of <see cref="Source"/> == "Request", this value is null as it 
        /// may be taken directly from the current http request context.
        /// </summary>
        public string Value { get; set; }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/ScriptParameter.cs
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    /// <summary>
    /// Right now, following assumption holds: Script's result value is properly formatted as sql value.
    /// If it is a string value, it is single-quoted in the stored json, if it's a numeric value or null, it is not quoted.
    /// Therefore, a script's result value can be taken as is and doesn't require any special treatment wrt type.
    /// </summary>
    public class ScriptParameter : StatementParameter
    {
        public string Script { get; }

        public ScriptParameter(string name, string script)
            : base(name)
        {
            Script = script ?? throw new ArgumentNullException(nameof(script));
        }

        public override async Task<string> ProvideSqlValue(StatementContext context, IDictionary<string, object> tableRow)
        {
            var result = await context.ScriptRunner.Execute(Script).ConfigureAwait(false);
            
            return result?.ToString();
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/ScriptConditionParameter.cs
using Microsoft.CodeAnalysis.CSharp.Scripting;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public class ScriptConditionParameter : ConditionParameter
    {
        public string Script { get; }

        public ScriptConditionParameter(string name, string script)
            : base(name)
        {
            Script = script ?? throw new ArgumentNullException(nameof(script));
        }

        public override Task<string> ProvideSqlValue(StatementContext context)
        {
            return context.ScriptRunner.Execute(Script);
        }
    }

}```

```csharp
// FILEPATH: ./StatementMetadata/ScriptGlobals.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    /// <summary>
    /// Globals provided to the csharp script execution environment to allow for access to external data, e.g. app settings.
    /// </summary>
    public class ScriptGlobals : IScriptGlobals
    {
        public ScriptGlobals(IServiceConfiguration serviceConfiguration)
        {
            Configuration = serviceConfiguration ?? throw new ArgumentNullException(nameof(serviceConfiguration));
        }

        public IServiceConfiguration Configuration { get; }
    }
}
```

```csharp
// FILEPATH: ./StatementMetadata/ConditionParameter.cs
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public abstract class ConditionParameter
    {
        public string Name { get; }

        protected ConditionParameter(string name)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
        }

        /// <summary>
        /// Provides the value of this condition parameter as valid sql, i.e. strings are quoted with single-quotes,
        /// numeric values are not quoted, ...
        /// </summary>
        /// <returns></returns>
        public abstract Task<string> ProvideSqlValue(StatementContext context);

        public static ConditionParameter CreateFrom(ConditionParameterEntity entity)
        {
            switch (entity.Source.ToLower())
            {
                case "request":
                    return new RequestConditionParameter(entity.Name);
                case "constant":
                    return new ConstantValueConditionParameter(entity.Name, entity.Value);
                case "script":
                    return new ScriptConditionParameter(entity.Name, entity.Value);
                default:
                    throw new InvalidOperationException("Cannot create Metadata.ConditionParameter from given Metadata.ConditionParameterEntity.");
            }
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/RequestConditionParameter.cs
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public class RequestConditionParameter : ConditionParameter
    {
        public RequestConditionParameter(string name)
            : base(name)
        {
        }

        public override Task<string> ProvideSqlValue(StatementContext context)
        {
            return Task.FromResult(context.RequestData.Get(Name));
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/ScriptExecution.cs
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public class ScriptExecution : IExecuteScripts
    {
        public IScriptGlobals Globals { get; }
        public CompiledScriptCache Cache { get; }

        public ScriptExecution(IScriptGlobals globals, CompiledScriptCache cache)
        {
            Globals = globals ?? throw new ArgumentNullException(nameof(globals));
            Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        }

        public Task<string> Execute(string script)
        {
            var runner = Cache.GetOrCache(script);

            return runner(Globals);
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/IExecuteScripts.cs
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public interface IExecuteScripts
    {
        Task<string> Execute(string script);
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/ParameterEntity.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public class ParameterEntity
    {
        /// <summary>
        /// Name of the parameter in the prepared statement
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Source of the value of the parameter represented as string (e.g. <see cref="TableParameter"/>, <see cref="ConstantValueParameter"/>, <see cref="ScriptParameter"/>)
        /// </summary>
        public string Source { get; set; }

        /// <summary>
        /// Value of the parameter; in case of <see cref="Source"/> == "Table", this value is null as it 
        /// may be taken directly from the <see cref="PreparedStatement.SourceTable"/> property.
        /// </summary>
        public string Value { get; set; }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/RequestParameter.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public class RequestParameter : StatementParameter
    {
        public RequestParameter(string name)
            : base(name)
        {
        }

        public override Task<string> ProvideSqlValue(StatementContext context, IDictionary<string, object> tableRow)
        {
            return Task.FromResult(context.RequestData?.Get(Name)?.ToString());
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/PreparedStatement.cs
using Dapper;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    /// <summary>
    /// Metadata describing a single prepared statement for a given range of db model versions. 
    /// </summary>
    public class PreparedStatement
    {
        // Deleted flag !!!

        public int Id { get; set; }

        public int DBModelVersionFrom { get; set; }

        public int DBModelSubVersionFrom { get; set; }

        public int DBModelVersionTo { get; set; }

        public int DBModelSubVersionTo { get; set; }

        public int SeqNr { get; set; }

        public DataDomain Domain { get; set; }

        public SqlCommand Command { get; set; }

        public string SourceTable { get; set; }

        public StatementParameter[] Parameters { get; set; }

        /// <summary>
        /// Description of conditions to be used when executing <see cref="SourceQuery"/>.
        /// </summary>
        public ConditionParameter[] SourceQueryConditions { get; set; }

        /// <summary>
        /// Description of conditions to be used when executing <see cref="ExecutionQuery"/>.
        /// </summary>
        public ConditionParameter[] ExecutionQueryConditions { get; set; }

        /// <summary>
        /// Query that is used to determine whether a single prepared statement must be executed at all. 
        /// If this query returns zero results, no transaction(s) are created for this prepared statement. 
        /// If it returns at least one result, transactions for this prepared statement are created.
        /// </summary>
        public string ExecutionQuery { get; set; }

        /// <summary>
        /// Query that is used to lookup the data required to "fill" transactions for a single prepared statement
        /// </summary>
        public string SourceQuery { get; set; }

        /// <summary>
        /// If true, this indicates that the prepared statement is a TTL Update statement for the <see cref="Domain"/>.
        /// This statement will always be returned to HU, even in the case when versions of domain in HU and cloud match.
        /// </summary>
        public bool IsTTLUpdate { get; set; }

        /// <summary>
        /// Returns an indication, whether this prepared statement is supported by a given db model version.
        /// </summary>
        /// <param name="dbModelVersion"></param>
        /// <param name="dbModelSubVersion"></param>
        /// <returns></returns>
        public bool SupportedByDbModelVersion(int dbModelVersion, int dbModelSubVersion)
        {
            return dbModelVersion >= DBModelVersionFrom
                && dbModelVersion <= DBModelVersionTo
                && dbModelSubVersion >= DBModelSubVersionFrom
                && dbModelSubVersion <= DBModelSubVersionTo;
        }

        public async Task<DynamicParameters> GetExecutionQueryParameters(StatementContext context)
        {
            if (ExecutionQuery == null) return null;

            var queryParams = new DynamicParameters();
            foreach (var param in ExecutionQueryConditions ?? Enumerable.Empty<ConditionParameter>())
            {
                queryParams.Add(param.Name, await param.ProvideSqlValue(context).ConfigureAwait(false));
            }

            return queryParams;
        }

        public async Task<List<Transaction>> CreateTransactions(IDbConnection connection, StatementContext context,CancellationToken cancellationToken)
        {
            var transactions = new List<Transaction>();

            if (Command.IsDeleteCommand())
            {
                var tx = await CreateTransaction(null, context).ConfigureAwait(false);

                transactions.Add(tx);
            }
            else
            {
                // For commands, that are not DELETE commands, we need to execute the SourceQuery to get data from database table.
                // There may still be statements that don't require data from table and will therefore not have a valid SourceQuery set.
                if (SourceQuery != null)
                {
                    var sqlQuery = SourceQuery;
                    var queryParams = new DynamicParameters();
                    foreach (var param in SourceQueryConditions ?? Enumerable.Empty<ConditionParameter>())
                    {
                        queryParams.Add(param.Name, await param.ProvideSqlValue(context).ConfigureAwait(false));
                    }
                    //IEnumerable<IDictionary<string,object>> results = null;
                    if (SLDBConfiguration.CacheablePreparedStatementSourceQuerySeqNrList.Contains(SeqNr))
                    {
                        IEnumerable<dynamic> results;
                        try
                        {
                            results = await connection.QueryCachedAsync(sqlQuery, queryParams, cancellationToken).ConfigureAwait(false);
                            foreach (var res in results)
                            {
                                var txs = await CreateTransaction(res, context).ConfigureAwait(false);
                                transactions.Add(txs);
                            }
                        }
                        catch
                        {

                            var command = new CommandDefinition(sqlQuery, queryParams, cancellationToken: cancellationToken);
                            results = await connection.QueryAsync(command).ConfigureAwait(false);
                            transactions.Clear();
                            foreach (var res in results)
                            {
                                var txs = await CreateTransaction(res, context).ConfigureAwait(false);
                                transactions.Add(txs);
                            }
                        }
                    }
                    else
                    {
                        var command = new CommandDefinition(sqlQuery, queryParams, cancellationToken: cancellationToken);
                        var results = await connection.QueryAsync(command).ConfigureAwait(false);
                        foreach (var res in results)
                        {
                            var txs = await CreateTransaction(res, context).ConfigureAwait(false);
                            transactions.Add(txs);
                        }
                    }
                }
                else
                {
                    var tx = await CreateTransaction(null, context).ConfigureAwait(false);
                    transactions.Add(tx);
                }
            }

            return transactions;
        }

        public async Task<Transaction> CreateTransaction(dynamic tableRow, StatementContext context)
        {
            var dict = (IDictionary<string, object>)tableRow;

            var transaction = new Transaction
            {
                StatementId = this.SeqNr
            };

            var txParams = new List<Parameter>(Parameters.Length);

            foreach (var p in Parameters)
            {
                txParams.Add(new Parameter(p.Name, (await p.ProvideSqlValue(context, dict).ConfigureAwait(false))));
            }

            transaction.Parameters = txParams.ToArray();

            return transaction;
        }

        public async Task<IEnumerable<dynamic>> GetExecutionQueryResult(IDbConnection connection, StatementContext context,CancellationToken cancellationToken)
        {
            if (ExecutionQuery == null) return null;

            var queryParams = new DynamicParameters();
            foreach (var param in ExecutionQueryConditions ?? Enumerable.Empty<ConditionParameter>())
            {
                queryParams.Add(param.Name, await param.ProvideSqlValue(context).ConfigureAwait(false));
            }
            if (SLDBConfiguration.CacheablePreparedStatementExecutionQuerySeqNrList.Contains(SeqNr))
            {
                return await connection.QueryCachedAsync(ExecutionQuery, queryParams, cancellationToken).ConfigureAwait(false);
            }
            var command = new CommandDefinition(ExecutionQuery, queryParams, cancellationToken: cancellationToken);
            return await connection.QueryAsync(command).ConfigureAwait(false);
        }

    }
}```

```csharp
// FILEPATH: ./StatementMetadata/ConditionParameterExtensions.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public static class ConditionParameterExtensions
    {
        public static bool IsRequestConditionParameter(this ConditionParameter parameter)
            => parameter is RequestConditionParameter;

        public static bool IsConstantValueConditionParameter(this ConditionParameter parameter)
            => parameter is ConstantValueConditionParameter;

        public static bool IsScriptConditionParameter(this ConditionParameter parameter)
            => parameter is ScriptConditionParameter;
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/IScriptGlobals.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public interface IScriptGlobals
    {
        IServiceConfiguration Configuration { get; }
    }
}
```

```csharp
// FILEPATH: ./StatementMetadata/ParameterExtensions.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public static class ParameterExtensions
    {
        public static bool IsTableParameter(this StatementParameter parameter)
            => parameter is TableParameter;

        public static bool IsConstantValueParameter(this StatementParameter parameter)
            => parameter is ConstantValueParameter;

        public static bool IsScriptParameter(this StatementParameter parameter)
            => parameter is ScriptParameter;

        public static bool IsRequestParameter(this StatementParameter parameter)
            => parameter is RequestParameter;
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/SqlCommand.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public class SqlCommand
    {
        public string Command { get; }

        internal protected SqlCommand(string command)
        {
            Command = command ?? throw new ArgumentNullException(nameof(command));
        }

        public override string ToString()
        {
            return Command;
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/PreparedStatementRepository.cs
using Dapper;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    // TODO: OPTIMIZE: Hold prepared statement meta data in memory.

    public class PreparedStatementRepository : IPreparedStatementRepository
    {
        public IConnectionFactory ConnectionFactory { get; }

        public TelemetryClient Logger { get; }

        private IEnumerable<PreparedStatement> _statements = null;
        private static Object syncObj = new object();
        public PreparedStatementRepository(IConnectionFactory connectionFactory, TelemetryClient logger)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
            Logger = logger ?? throw new ArgumentNullException(nameof(connectionFactory));
            init();
        }

        public bool init()
        {
            //Logger.TrackTrace("Creating instance of PreparedStatementRepository");
            if (_statements == null)
            {
                lock (syncObj)
                {
                    if (_statements == null)
                    {
                        const string sql = "SELECT * FROM preparedStatementMetadataTable";
                        using (var connection = ConnectionFactory.Create())
                        {
                            _statements = connection.Query<PreparedStatement>(sql);
                        }
                    }
                }
            }
            //Logger.TrackTrace("Created instance of PreparedStatementRepository");
            return true;
        }

        public async Task<IEnumerable<PreparedStatement>> FindAll()
        {
            //Logger.TrackTrace(String.Format("_statements = {0}", _statements));
            return await Task.FromResult(_statements).ConfigureAwait(false);
        }

        public async Task<IEnumerable<PreparedStatement>> FindForDomainAndVersion(DataDomain domain, Version version)
        {
            var statements = await FindAll().ConfigureAwait(false);

            return statements.Where(x => x.Domain == domain && x.SupportedByDbModelVersion(version.Major, version.Minor));
        }

        public async Task<IEnumerable<PreparedStatement>> FindTTLUpdatesForDomainAndVersion(DataDomain domain, Version version)
        {
            var statements = await FindForDomainAndVersion(domain, version).ConfigureAwait(false);

            return statements.Where(x => x.IsTTLUpdate);
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/SqlCommandExtensions.cs
using System;
using System.Linq;

namespace SLDBService.StatementMetadata
{
    public static class SqlCommandExtensions
    {
        public static bool IsUpdateCommand(this SqlCommand command) => command == SqlCommands.Update;
        public static bool IsInsertCommand(this SqlCommand command) => command == SqlCommands.Insert;
        public static bool IsUpsertCommand(this SqlCommand command) => command == SqlCommands.Upsert;
        public static bool IsDeleteCommand(this SqlCommand command) => command == SqlCommands.Delete;

    }
}```

```csharp
// FILEPATH: ./StatementMetadata/IServiceConfiguration.cs
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public interface IServiceConfiguration
    {
        int GetIntValue(string setting);

        string GetStringValue(string setting);
    }
}
```

```csharp
// FILEPATH: ./StatementMetadata/IPreparedStatementRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public interface IPreparedStatementRepository
    {
        Task<IEnumerable<PreparedStatement>> FindAll();
        Task<IEnumerable<PreparedStatement>> FindForDomainAndVersion(DataDomain domain, Version version);
        Task<IEnumerable<PreparedStatement>> FindTTLUpdatesForDomainAndVersion(DataDomain domain, Version version);
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/TableParameter.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    public class TableParameter : StatementParameter
    {
        public TableParameter(string name) 
            : base(name)
        {
        }

        public override Task<string> ProvideSqlValue(StatementContext context, IDictionary<string, object> tableRow)
        {
            return Task.FromResult(tableRow[Name]?.ToString());
        }
    }
}```

```csharp
// FILEPATH: ./StatementMetadata/ConstantValueParameter.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.StatementMetadata
{
    /// <summary>
    /// Right now, following assumption holds: Constant value is properly formatted in sql table.
    /// If it is a string value, it is single-quoted in the stored json, if it's a numeric value or null, it is not quoted.
    /// Therefore, a constant value parameter value can be taken as is and doesn't require any special treatment wrt type.
    /// </summary>
    public class ConstantValueParameter : StatementParameter
    {
        public object Value { get; }
        
        public ConstantValueParameter(string name, object value)
            : base(name)
        {
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public override Task<string> ProvideSqlValue(StatementContext context, IDictionary<string, object> tableRow)
        {
            return Task.FromResult(Value?.ToString());
        }
    }
}```

```csharp
// FILEPATH: ./Models/Transaction.cs
namespace SLDBService.Models
{
    /// <summary>
    /// Single prepared statement to be executed on client.
    /// </summary>
    public class Transaction
    {
        /// <summary>
        /// Id of prepeared statement
        /// </summary>
        public int StatementId { get; set; }

        /// <summary>
        /// Parameter names and values for this prepared statement
        /// </summary>
        public Parameter[] Parameters { get; set; }

    }
}
```

```csharp
// FILEPATH: ./Models/DemoRequest.cs
using MediatR;
using System;
using System.Linq;

namespace SLDBService.Models
{
    /// <summary>
    /// Harman demo request
    /// </summary>
    public class DemoRequest : IRequest<DemoResponse>
    {
        public SLDBDataSetVersionCheck SLDBDataSetVersionCheck { get; set; }
    }
    
    public class SLDBDataSetVersionCheck
    {
        public string version { get; set; }
        public Systeminformation systemInformation { get; set; }
        public Vehicletype vehicleType { get; set; }
        public Station[] stations { get; set; }
        public string[] required { get; set; }
    }

    public class Systeminformation
    {
        public string ntg { get; set; }
        public string HUHW { get; set; }
        public string release { get; set; }
        public string dBModelVersion { get; set; }
        public string dBModelSubVersion { get; set; }
        public string dBVersion { get; set; }
        public string dBSubVersion { get; set; }
        public string regID { get; set; }
        public string dBProductName { get; set; }
        public string dBSupplier { get; set; }
    }

    public class Vehicletype
    {
        public string carline { get; set; }
        public string variant { get; set; }
        public string modelYear { get; set; }
    }

    public class Station
    {
        public string linkingID { get; set; }
        public string dataSetVersion { get; set; }
        public string StationLogoID { get; set; }
        public string LogoVersion { get; set; }
        public string PhoneticVersion { get; set; }
        public string LocationLat { get; set; }
        public string LocationLon { get; set; }
        public string frequency { get; set; }
        public string transmitterID { get; set; }
        public string broadcastStandard { get; set; }
        public string subchannel { get; set; }
        public string subChannelId { get; set; }
        public string broadcastedStationName { get; set; }
        public string ECC { get; set; }
        public string ensembleID { get; set; }
        public string FM_PI { get; set; }
        public string DABSID { get; set; }
        public string SCIDI { get; set; }
    }

}```

```csharp
// FILEPATH: ./Models/UnknownStationTableEntity.cs
using Microsoft.WindowsAzure.Storage.Table;

namespace SLDBService.Models
{
    /// <summary>
    /// PartitionKey: Date formatted as "yyyy-MM-dd"
    /// RowKey: Time formatted as "HH:mm:ss.fff"
    /// So each partition contains the unknown stations for a single day.
    /// </summary>
    public class UnknownStationTableEntity : TableEntity
    {
        public UnknownStationTableEntity()
        {
        }

        public UnknownStationTableEntity(string partitionKey, string rowKey) 
            : base(partitionKey, rowKey)
        {
        }


        public string RawJson { get; set; }
        /*
        public string Reason { get; set; }
        public int HandleNumber { get; set; }
        public int dBVersion { get; set; }
        public int dBSubVersion { get; set; }
        public int dBModelVersion { get; set; }
        public int dBModelSubVersion { get; set; }
        public int regionId { get; set; }
        public int TempOrLinkingId { get; set; }
        public double LatRound { get; set; }
        public double LongRound { get; set; }
        public int BroadcastStandard { get; set; }
        public string StationIdentificationMatches { get; set; }
        public int Frequency { get; set; }
        public int SubchannelID { get; set; }
        public int RecLevel { get; set; }
        public string SNR { get; set; }
        public string BER { get; set; }
        public string HUQLevel { get; set; }
        public int StationId { get; set; }
        public int ECC { get; set; }
        public int EnsBouqTSId { get; set; }
        public int ONID { get; set; }
        public string StationNameShort { get; set; }
        public string StationNameLong { get; set; }
        public int PTY { get; set; }
        public string OTALogo { get; set; }
        public string OTALogoTransaprency { get; set; }
        public string OTASlideshow { get; set; }
        public string Kbps { get; set; }
        public string Stereo { get; set; }
        public bool TPFlag { get; set; }
        public bool RollingPS { get; set; }
        public string Intermod { get; set; }
        public string CoChannel { get; set; }

        public string HUTimestamp { get; set; }
        */
    }
}```

```csharp
// FILEPATH: ./Models/BaseDataVersionCheckResponse.cs
using Newtonsoft.Json;

namespace SLDBService.Models
{
    /// <summary>
    /// Base data version response.
    /// </summary>
    public class BaseDataVersionCheckResponse
    {
        public BaseDataVersionCheckResponse()
        {
            Status = ResultStatus.Success;
        }

        /// <summary>
        /// Opaque number sent by HU client and will be returned unprocessed with response.
        /// </summary>
        public int HandleNumber { get; set; }

        /// <summary>
        /// Station linking id
        /// </summary>
        public int LinkingId { get; set; }

        [JsonIgnore]
        public string BASTransactions { get; set; }
        
        /// <summary>
        /// Prepeared statements to be executed on client.
        /// </summary>
        public Transaction[] Transactions { get; set; }

        /// <summary>
        /// Prepared statements to be executed on client. Each transaction contains a link to an image and a md5 checksum.
        /// </summary>
        public ImageTransaction[] ImageTransactions { get; set; }

        /// <summary>
        /// Indication on status of response.
        /// </summary>
        [JsonIgnore]
        public ResultStatus Status { get; set; }

        public static BaseDataVersionCheckResponse NotFound()
            => new BaseDataVersionCheckResponse { Status = ResultStatus.NotFound };

        public static BaseDataVersionCheckResponse NotModified()
            => new BaseDataVersionCheckResponse { Status = ResultStatus.NotModified };
    }
}
```

```csharp
// FILEPATH: ./Models/ReceptionAreaVersionCheckResponse.cs
using Newtonsoft.Json;

namespace SLDBService.Models
{
    public class ReceptionAreaVersionCheckResponse
    {
        public ReceptionAreaVersionCheckResponse()
        {
            Status = ResultStatus.Success;
        }

        /// <summary>
        /// Opaque number sent by HU client and will be returned unprocessed with response.
        /// </summary>
        public int HandleNumber { get; set; }

        /// <summary>
        /// Prepared statements to be executed on client.
        /// </summary>
        public Transaction[] Transactions { get; set; }

        /// <summary>
        /// Indication on status of response.
        /// </summary>
        [JsonIgnore]
        public ResultStatus Status { get; set; }

        public static ReceptionAreaVersionCheckResponse NotFound()
            => new ReceptionAreaVersionCheckResponse { Status = ResultStatus.NotFound };

        public static ReceptionAreaVersionCheckResponse NotModified()
            => new ReceptionAreaVersionCheckResponse { Status = ResultStatus.NotModified };
    }
}
```

```csharp
// FILEPATH: ./Models/ProductDbTable.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.Models
{
    public class ProductDbTable : ISLDBTable
    {
        public int ProductId { get; set; }
        public int SupplierId { get; set; }
        public int dBVersion { get; set; }
        public int dBSubVersion { get; set; }
        public int dBModelVersion { get; set; }
        public string ProductName { get; set; }
        public int dBModelSubVersion { get; set; }
        public int regionId { get; set; }
        public int versionBAS { get; set; }

        public Parameter[] ToStatementParameters()
        {
            return new Parameter[]
                {
                    new Parameter(nameof(ProductId),ProductId.ToString()),
                    new Parameter(nameof(SupplierId),SupplierId.ToString()),
                    new Parameter(nameof(dBVersion),dBVersion.ToString()),
                    new Parameter(nameof(dBSubVersion),dBSubVersion.ToString()),
                    new Parameter(nameof(dBModelVersion),dBModelVersion.ToString()),
                    new Parameter(nameof(ProductName),ProductName.ToString()),
                    new Parameter(nameof(dBModelSubVersion),dBModelSubVersion.ToString()),
                    new Parameter(nameof(regionId),regionId.ToString()),
                    new Parameter(nameof(versionBAS),versionBAS.ToString())
                };
        }
    }

}
```

```csharp
// FILEPATH: ./Models/ResetSldbResponse.cs
using Newtonsoft.Json;
using System.Net;

namespace SLDBService.Models
{
    public class ResetSldbResponse
    {
        private ResetSldbResponse()
        {
        }

        [JsonIgnore]
        public ResultStatus Status { get; private set; }

        public static ResetSldbResponse NotAllowed()
            => new ResetSldbResponse { Status = ResultStatus.NotFound };

        public static ResetSldbResponse Success()
            => new ResetSldbResponse { Status = ResultStatus.Success };

    }
}
```

```csharp
// FILEPATH: ./Models/UnknownStationResponse.cs
using Newtonsoft.Json;

namespace SLDBService.Models
{
    public class UnknownStationResponse
    {
        public UnknownStationResponse()
        {
            Status = ResultStatus.Success;
        }

        /// <summary>
        /// Opaque number sent by HU client and will be returned unprocessed with response.
        /// </summary>
        public int HandleNumber { get; set; }

        public int TempOrLinkingId { get; set; }

        public int LinkingId { get; set; }

        public int LogoId { get; set; }

        /// <summary>
        /// Prepeared statements to be executed on client.
        /// </summary>
        public Transaction[] Transactions { get; set; }

        /// <summary>
        /// Prepared statements to be executed on client. Each transaction contains a link to an image and a md5 checksum.
        /// </summary>
        public ImageTransaction[] ImageTransactions { get; set; }

        /// <summary>
        /// Indication on status of response.
        /// </summary>
        [JsonIgnore]
        public ResultStatus Status { get; set; }

        public static UnknownStationResponse NotFound()
            => new UnknownStationResponse { Status = ResultStatus.NotFound };
    }
}```

```csharp
// FILEPATH: ./Models/ImageTransaction.cs
namespace SLDBService.Models
{
    /// <summary>
    /// Single prepared statement to be executed on client. Also contains an image reference.
    /// </summary>
    public class ImageTransaction : Transaction
    {
        /// <summary>
        /// Url pointing to an image
        /// </summary>
        public string ImageLink { get; set; }

        /// <summary>
        /// Base64 encoded MD5 hash of image at url <see cref="ImageLink"/>.
        /// </summary>
        public string ImageMD5Base64 { get; set; }
    }
}
```

```csharp
// FILEPATH: ./Models/ServiceLogoFormatTable.cs
using SLDBService.Models;
using System;

namespace SLDBService.Models
{
    public class ServiceLogoFormatTable : ISLDBTable
    {
        public int stationLogoFormatId { get; set; }
        public string logoSizeAndStyle { get; set; }
        public int logoHeightInPixels { get; set; }
        public int logoWidthInPixels { get; set; }

        public Parameter[] ToStatementParameters()
        {
            return new Parameter[]
            {
                new Parameter(nameof(stationLogoFormatId), stationLogoFormatId.ToString()),
                new Parameter(nameof(logoSizeAndStyle), logoSizeAndStyle.ToString()),
                new Parameter(nameof(logoHeightInPixels), logoHeightInPixels.ToString()),
                new Parameter(nameof(logoWidthInPixels), logoWidthInPixels.ToString())
            };
        }
    }
}```

```csharp
// FILEPATH: ./Models/StationLogoRequest.cs
using MediatR;

namespace SLDBService.Models
{
    /// <summary>
    /// Request sent by client in order to retrieve a station logo
    /// </summary>
    public class StationLogoRequest : IRequest<StationLogoResponse>
    {
        /// <summary>
        /// Station linking id
        /// </summary>
        public int LinkingId { get; set; }

        /// <summary>
        /// Station logo id
        /// </summary>
        public int LogoId { get; set; }

        /// <summary>
        /// Logo format
        /// </summary>
        public int Format { get; set; }

        /// <summary>
        /// Logo version
        /// </summary>
        public int Version { get; set; }

        public override string ToString()
        {
            return $"LinkingId {LinkingId} / LogoId {LogoId} / Version {Version} / Format {Format}";
        }
    }

}```

```csharp
// FILEPATH: ./Models/ServiceLogoTable.cs
using SLDBService.Models;
using System;
using System.Linq;

namespace SLDBService.Models
{
    public class ServiceLogoTable : ISLDBTable
    {
        public int StationLogoId { get; set; }
        public int stationLogoFormatId { get; set; }
        public byte[] stationLogoData { get; set; }
        public int? BorderColor { get; set; }
        public int BackgroundColor { get; set; }
        public int versionLOG { get; set; }
        public int? stationLogoTextPosX { get; set; }
        public int? stationLogoTextPosY { get; set; }
        public int? stationLogoTextFontColor { get; set; }
        public int? stationLogoTextFontType { get; set; }
        public int? stationLogoTextFontSize { get; set; }

        public Parameter[] ToStatementParameters()
        {
            return new Parameter[]
            {
                new Parameter(nameof(StationLogoId), StationLogoId.ToString()),
                new Parameter(nameof(stationLogoFormatId), stationLogoFormatId.ToString()),
                new Parameter(nameof(BorderColor), BorderColor?.ToString() ?? null),
                new Parameter(nameof(BackgroundColor), BackgroundColor.ToString()),
                new Parameter(nameof(versionLOG), versionLOG.ToString()),
                new Parameter(nameof(stationLogoTextPosX), stationLogoTextPosX?.ToString() ?? null),
                new Parameter(nameof(stationLogoTextPosY), stationLogoTextPosY?.ToString() ?? null),
                new Parameter(nameof(stationLogoTextFontColor), stationLogoTextFontColor?.ToString() ?? null),
                new Parameter(nameof(stationLogoTextFontType), stationLogoTextFontType?.ToString() ?? null),
                new Parameter(nameof(stationLogoTextFontSize), stationLogoTextFontSize?.ToString() ?? null),

            };
        }
    }
}```

```csharp
// FILEPATH: ./Models/DemoResponse.cs
using Newtonsoft.Json;

namespace SLDBService.Models
{
    /// <summary>
    /// Used for "Hello World" implementation only. Harman demo response.
    /// to return.
    /// </summary>
    public class DemoResponse
    {
        public SLDBDataSetVersionResponse SLDBDataSetVersionResponse { get; set; }
    }

    public class SLDBDataSetVersionResponse
    {
        public string version { get; set; }
        public string processingStatus { get; set; }
        public string[] UpToDateLinkingIDs { get; set; }
        public string[] UnknownLinkingIDs { get; set; }
        public Outdatedlinkingid[] OutDatedLinkingIDs { get; set; }
        public Preparedstatementvalue[] PreparedStatementValues { get; set; }
    }

    public class Outdatedlinkingid
    {
        public string linkingID { get; set; }
        public string LinkingIDStatus { get; set; }
        public string NewLinkingID { get; set; }
        public string TTL { get; set; }
        public string OnlineDataSetVersion { get; set; }
        public bool invalid { get; set; }
    }

    public class Preparedstatementvalue
    {
        public string SequenceID { get; set; }
        public Keyvaluelist[] keyvaluelist { get; set; }
    }

    public class Keyvaluelist
    {
        public string StationLogoId { get; set; }
        public string stationLogoFormatId { get; set; }
        public string BorderColor { get; set; }
    }

}
```

```csharp
// FILEPATH: ./Models/UnknownStationRequest.cs
using System;
using System.Collections.Generic;
using MediatR;
using Microsoft.WindowsAzure.Storage;
using Newtonsoft.Json;
using SLDBService.StatementMetadata;

namespace SLDBService.Models
{
    public class UnknownStationRequest : IRequest<UnknownStationResponse>,IHttpRequestData
    {
        public int HandleNumber { get; set; }
        public int dBVersion { get; set; }
        public int dBSubVersion { get; set; }
        public int dBModelVersion { get; set; }
        public int dBModelSubVersion { get; set; }
        public int regionId { get; set; }
        public int TempOrLinkingId { get; set; }
        public double LatRound { get; set; }
        public double LongRound { get; set; }
        public int BroadcastStandard { get; set; }
        public string StationIdentificationMatches { get; set; }
        public int Frequency { get; set; }
        public int SubchannelID { get; set; }
        public int RecLevel { get; set; }
        public string SNR { get; set; }
        public string BER { get; set; }
        public string HUQLevel { get; set; }
        public int StationId { get; set; }
        public int ECC { get; set; }
        public int EnsBouqTSId { get; set; }
        public int ONID { get; set; }
        public string StationNameShort { get; set; }
        public string StationNameLong { get; set; }
        public int PTY { get; set; }
        public string OTALogo { get; set; }
        public string OTALogoTransaprency { get; set; }
        public string OTASlideshow { get; set; }
        public string Kbps { get; set; }
        public string Stereo { get; set; }
        public bool TPFlag { get; set; }
        public bool RollingPS { get; set; }
        public string Intermod { get; set; }
        public string CoChannel { get; set; }

        // Format sample: 2007-08-31T16:47+00:00
        public string TimeStamp { get; set; }

        /// <summary>
        /// Function that can be used to create a image link.
        /// </summary>
        [JsonIgnore]
        public CreateImageLinkDelegate CreateImageLink { get; set; }

        public string Get(string property)
        {
            if(String.Equals(property, "HandleNumber", StringComparison.OrdinalIgnoreCase))
                return HandleNumber.ToString();
            if(String.Equals(property, "dBVersion", StringComparison.OrdinalIgnoreCase))
                return dBVersion.ToString();
            if(String.Equals(property, "dBSubVersion", StringComparison.OrdinalIgnoreCase))
                return dBSubVersion.ToString();
            if(String.Equals(property, "dBModelVersion", StringComparison.OrdinalIgnoreCase))
                return dBModelVersion.ToString();
            if(String.Equals(property, "dBModelSubVersion", StringComparison.OrdinalIgnoreCase))
                return dBModelSubVersion.ToString();
            if(String.Equals(property, "regionId", StringComparison.OrdinalIgnoreCase))
                return regionId.ToString();
            if(String.Equals(property, "TempOrLinkingId", StringComparison.OrdinalIgnoreCase) || String.Equals(property, "linkingId", StringComparison.OrdinalIgnoreCase))
                return TempOrLinkingId.ToString();
            if(String.Equals(property, "LatRound", StringComparison.OrdinalIgnoreCase)) 
                return LatRound.ToString();
            if(String.Equals(property, "LongRound", StringComparison.OrdinalIgnoreCase))
                return LongRound.ToString();
            if(String.Equals(property, "BroadcastStandard", StringComparison.OrdinalIgnoreCase))
                return BroadcastStandard.ToString();
            if(String.Equals(property, "StationIdentificationMatches", StringComparison.OrdinalIgnoreCase))
                return StationIdentificationMatches;
            if(String.Equals(property, "Frequency", StringComparison.OrdinalIgnoreCase))
                return Frequency.ToString();
            if(String.Equals(property, "SubchannelID", StringComparison.OrdinalIgnoreCase))
                return SubchannelID.ToString();
            if(String.Equals(property, "RecLevel", StringComparison.OrdinalIgnoreCase))
                return RecLevel.ToString();
            if(String.Equals(property, "SNR", StringComparison.OrdinalIgnoreCase))
                return SNR;
            if(String.Equals(property, "BER", StringComparison.OrdinalIgnoreCase))
                return BER;
            if(String.Equals(property, "HUQLevel", StringComparison.OrdinalIgnoreCase))
                return HUQLevel;
            if(String.Equals(property, "StationId", StringComparison.OrdinalIgnoreCase))
                return StationId.ToString();
            if(String.Equals(property, "ECC", StringComparison.OrdinalIgnoreCase))  
                return ECC.ToString();
            if(String.Equals(property, "EnsBouqTSId", StringComparison.OrdinalIgnoreCase))
                return EnsBouqTSId.ToString();
            if(String.Equals(property, "ONID", StringComparison.OrdinalIgnoreCase))
                return ONID.ToString();
            if(String.Equals(property, "StationNameShort", StringComparison.OrdinalIgnoreCase))
                return StationNameShort;
            if(String.Equals(property, "StationNameLong", StringComparison.OrdinalIgnoreCase))  
                return StationNameLong;
            if(String.Equals(property, "PTY", StringComparison.OrdinalIgnoreCase))
                return PTY.ToString();
            if(String.Equals(property, "OTALogo", StringComparison.OrdinalIgnoreCase))
                return OTALogo;
            if(String.Equals(property, "OTALogoTransaprency", StringComparison.OrdinalIgnoreCase))
                return OTALogoTransaprency;
            if(String.Equals(property, "OTASlideshow", StringComparison.OrdinalIgnoreCase))
                return OTASlideshow;
            if(String.Equals(property, "Kbps", StringComparison.OrdinalIgnoreCase))
                return Kbps;
            if(String.Equals(property, "Stereo", StringComparison.OrdinalIgnoreCase))
                return Stereo;
            if(String.Equals(property, "TPFlag", StringComparison.OrdinalIgnoreCase))
                return TPFlag.ToString();
            if(String.Equals(property, "RollingPS", StringComparison.OrdinalIgnoreCase))
                return RollingPS.ToString();
            if(String.Equals(property, "Intermod", StringComparison.OrdinalIgnoreCase))
                return Intermod;
            if(String.Equals(property, "CoChannel", StringComparison.OrdinalIgnoreCase))
                return CoChannel;
            if(String.Equals(property, "TimeStamp", StringComparison.OrdinalIgnoreCase))
                return TimeStamp;
            else{
                throw new Exception($"Property '{property}' not found on type '{GetType().FullName}'");
            }    
        }
    }
}```

```csharp
// FILEPATH: ./Models/MuxVersionCheckResponse.cs
using Newtonsoft.Json;

namespace SLDBService.Models
{
    public class MuxVersionCheckResponse
    {
        public MuxVersionCheckResponse()
        {
            Status = ResultStatus.Success;
        }

        /// <summary>
        /// Opaque number sent by HU client and will be returned unprocessed with response.
        /// </summary>
        public int HandleNumber { get; set; }

        /// <summary>
        /// Prepared statements to be executed on client.
        /// </summary>
        public Transaction[] Transactions { get; set; }

        /// <summary>
        /// Indication on status of response.
        /// </summary>
        [JsonIgnore]
        public ResultStatus Status { get; set; }

        public static MuxVersionCheckResponse NotFound()
            => new MuxVersionCheckResponse { Status = ResultStatus.NotFound };

        public static MuxVersionCheckResponse NotModified()
            => new MuxVersionCheckResponse { Status = ResultStatus.NotModified };
    }
}
```

```csharp
// FILEPATH: ./Models/BaseDataVersionCheckRequest.cs
using MediatR;
using Newtonsoft.Json;
using SLDBService.StatementMetadata;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Threading.Tasks;

namespace SLDBService.Models
{
    /// <summary>
    /// SLDB version check request
    /// </summary>
    public class BaseDataVersionCheckRequest : IRequest<BaseDataVersionCheckResponse>, IHttpRequestData
    {
        /// <summary>
        /// Used by HU client. Not processed on server, value is returned as it is in response.
        /// </summary>
        public int HandleNumber { get; set; }

        /// <summary>
        /// Station linking id
        /// </summary>
        public int LinkingId { get; set; }

        /// <summary>
        /// Requested logo id
        /// </summary>
        public int LogoId { get; set; }

        /// <summary>
        /// Current version of base domain on client.
        /// </summary>
        public int VersionBAS { get; set; }

        /// <summary>
        /// Current version of metadata domain on client.
        /// </summary>
        public int VersionMET { get; set; }

        /// <summary>
        /// Current version of genre domain on client.
        /// </summary>
        public int VersionGEN { get; set; }

        /// <summary>
        /// Current version of phonetics domain on client.
        /// </summary>
        public int VersionPHO { get; set; }

        /// <summary>
        /// Current version of logo on client.
        /// </summary>
        public int VersionLOG { get; set; }

        [JsonIgnore]
        public Version DbModelVersion { get; set; }

        [JsonIgnore]
        public bool SkipBASDomain { get; set; } = false;

        /// <summary>
        /// Function that can be used to create a image link.
        /// </summary>
        [JsonIgnore]
        public CreateImageLinkDelegate CreateImageLink { get; set; }

        public string Get(string property)
        {
            // There are good options to perform the task of dynamic property lookup (like FastMember or hand crafted expression trees),
            // but nothing beats the hand-written code in terms of performance.
            // In order to make sure, the hand-written code doesn't miss a property, a simple unit test is used for verification.
            if (String.Equals(nameof(HandleNumber), property, StringComparison.OrdinalIgnoreCase))
            {
                return HandleNumber.ToString();
            }
            else if (String.Equals(nameof(LinkingId), property, StringComparison.OrdinalIgnoreCase))
            {
                return LinkingId.ToString();
            }
            else if (String.Equals(nameof(LogoId), property, StringComparison.OrdinalIgnoreCase))
            {
                return LogoId.ToString();
            }
            else if (String.Equals(nameof(VersionBAS), property, StringComparison.OrdinalIgnoreCase))
            {
                return VersionBAS.ToString();
            }
            else if (String.Equals(nameof(VersionMET), property, StringComparison.OrdinalIgnoreCase))
            {
                return VersionMET.ToString();
            }
            else if (String.Equals(nameof(VersionGEN), property, StringComparison.OrdinalIgnoreCase))
            {
                return VersionGEN.ToString();
            }
            else if (String.Equals(nameof(VersionPHO), property, StringComparison.OrdinalIgnoreCase))
            {
                return VersionPHO.ToString();
            }
            else if (String.Equals(nameof(VersionLOG), property, StringComparison.OrdinalIgnoreCase))
            {
                return VersionLOG.ToString();
            }
            else
            {
                throw new Exception($"Property '{property}' not found on type '{GetType().FullName}'");
            }
        }

    }
}```

```csharp
// FILEPATH: ./Models/Parameter.cs
using Newtonsoft.Json;

namespace SLDBService.Models
{
    /// <summary>
    /// Name and value of a single parameter of a prepared statement.
    /// </summary>
    public class Parameter
    {
        public Parameter(string placeholder, string placeholderValue)
        {
            Placeholder = placeholder;
            PlaceholderValue = placeholderValue;
        }

        /// <summary>
        /// Parameter name in prepared statement
        /// </summary>
        [JsonProperty("K")]
        public string Placeholder { get; set; }

        /// <summary>
        /// Value of parameter in prepared statement
        /// </summary>
        [JsonProperty("V")]
        public string PlaceholderValue { get; set; }
    }
}
```

```csharp
// FILEPATH: ./Models/ReceptionAreaVersionCheckRequest.cs
using MediatR;
using Newtonsoft.Json;
using SLDBService.StatementMetadata;
using System;

namespace SLDBService.Models
{
    public class ReceptionAreaVersionCheckRequest : IRequest<ReceptionAreaVersionCheckResponse>, IHttpRequestData
    {
        /// <summary>
        /// Used by HU client. Not processed on server, value is returned as it is in response.
        /// </summary>
        public int HandleNumber { get; set; }

        /// <summary>
        /// Reception Area Id
        /// </summary>
        public int ReceptionAreaId { get; set; }

        /// <summary>
        /// Mux Id
        /// </summary>
        public int MuxId { get; set; }

        /// <summary>
        /// Frequency Id
        /// </summary>
        public int FrequencyId { get; set; }

        /// <summary>
        /// Transmitter Id
        /// </summary>
        public int TransmitterId { get; set; }

        /// <summary>
        /// Current version of reception area domain on client.
        /// </summary>
        public int VersionREC { get; set; }

        [JsonIgnore]
        public Version DbModelVersion { get; set; }

        public string Get(string property)
        {
            // There are good options to perform the task of dynamic property lookup (like FastMember or hand crafted expression trees),
            // but nothing beats the hand-written code in terms of performance.
            // In order to make sure, the hand-written code doesn't miss a property, a simple unit test is used for verification.
            if (String.Equals(nameof(HandleNumber), property, StringComparison.OrdinalIgnoreCase))
            {
                return HandleNumber.ToString();
            }
            else if (String.Equals(nameof(ReceptionAreaId), property, StringComparison.OrdinalIgnoreCase))
            {
                return ReceptionAreaId.ToString();
            }
            else if (String.Equals(nameof(MuxId), property, StringComparison.OrdinalIgnoreCase))
            {
                return MuxId.ToString();
            }
            else if (String.Equals(nameof(FrequencyId), property, StringComparison.OrdinalIgnoreCase))
            {
                return FrequencyId.ToString();
            }
            else if (String.Equals(nameof(TransmitterId), property, StringComparison.OrdinalIgnoreCase))
            {
                return TransmitterId.ToString();
            }
            else if (String.Equals(nameof(VersionREC), property, StringComparison.OrdinalIgnoreCase))
            {
                return VersionREC.ToString();
            }
            else
            {
                throw new Exception($"Property '{property}' not found on type '{GetType().FullName}'");
            }
        }
    }
}```

```csharp
// FILEPATH: ./Models/MuxVersionCheckRequest.cs
using MediatR;
using Newtonsoft.Json;
using SLDBService.StatementMetadata;
using System;

namespace SLDBService.Models
{
    public class MuxVersionCheckRequest : IRequest<MuxVersionCheckResponse>, IHttpRequestData
    {
        /// <summary>
        /// Used by HU client. Not processed on server, value is returned as it is in response.
        /// </summary>
        public int HandleNumber { get; set; }

        /// <summary>
        /// Mux Id
        /// </summary>
        public int MuxId { get; set; }

        /// <summary>
        /// Linking Id
        /// </summary>
        public int LinkingId { get; set; }

        /// <summary>
        /// Current version of mux domain on client.
        /// </summary>
        public int VersionMUX { get; set; }

        [JsonIgnore]
        public Version DbModelVersion { get; set; }

        public string Get(string property)
        {
            // There are good options to perform the task of dynamic property lookup (like FastMember or hand crafted expression trees),
            // but nothing beats the hand-written code in terms of performance.
            // In order to make sure, the hand-written code doesn't miss a property, a simple unit test is used for verification.
            if (String.Equals(nameof(HandleNumber), property, StringComparison.OrdinalIgnoreCase))
            {
                return HandleNumber.ToString();
            }
            else if (String.Equals(nameof(MuxId), property, StringComparison.OrdinalIgnoreCase))
            {
                return MuxId.ToString();
            }
            else if (String.Equals(nameof(LinkingId), property, StringComparison.OrdinalIgnoreCase))
            {
                return LinkingId.ToString();
            }
            else if (String.Equals(nameof(VersionMUX), property, StringComparison.OrdinalIgnoreCase))
            {
                return VersionMUX.ToString();
            }
            else
            {
                throw new Exception($"Property '{property}' not found on type '{GetType().FullName}'");
            }
        }
    }
}```

```csharp
// FILEPATH: ./Models/ResultStatus.cs
namespace SLDBService.Models
{
    public enum ResultStatus
    {
        Success,
        NotFound,
        NotModified
    }
}
```

```csharp
// FILEPATH: ./Models/ISLDBTable.cs
namespace SLDBService.Models
{
    /// <summary>
    /// Marker interface for models that represent a table from sldb database.
    /// </summary>
    public interface ISLDBTable
    {
    }

}```

```csharp
// FILEPATH: ./Models/StationLogoResponse.cs
using System;

namespace SLDBService.Models
{
    /// <summary>
    /// Response to a <see cref="StationLogoRequest"/> containing station logo as byte[].
    /// </summary>
    public class StationLogoResponse
    {
        public static readonly StationLogoResponse NotFound = new StationLogoResponse();

        private StationLogoResponse()
        {
            Success = false;
        }

        public StationLogoResponse(byte[] logoData)
        {
            LogoData = logoData ?? throw new ArgumentNullException(nameof(logoData));
            Success = true;
        }

        public bool Success { get; }

        public byte[] LogoData { get; }

        public override string ToString()
        {
            return $"Success {Success} / Size of LogoData {LogoData?.Length}";
        }
    }
}```

```csharp
// FILEPATH: ./Models/ResetSldbRequest.cs
using MediatR;
using Newtonsoft.Json;
using System;

namespace SLDBService.Models
{
    public class ResetSldbRequest : IRequest<ResetSldbResponse>
    {
        public string Status { get; set; }
        public string version { get; set; }

        [JsonIgnore]
        public bool ConfirmsReset => String.Equals(Status, "confirm", StringComparison.OrdinalIgnoreCase);

        [JsonIgnore]
        public bool FinishesReset => String.Equals(Status, "finished", StringComparison.OrdinalIgnoreCase);
    }
}
```

```csharp
// FILEPATH: ./Models/CreateImageLinkDelegate.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace SLDBService.Models
{
    /// <summary>
    /// Creates án image link for the given parameters that can be used to query the linked image from this service.
    /// </summary>
    /// <param name="linkingId"></param>
    /// <param name="logoId"></param>
    /// <param name="version"></param>
    /// <param name="format"></param>
    /// <returns></returns>
    public delegate string CreateImageLinkDelegate(int linkingId, int logoId, int version, int format);

}```

```csharp
// FILEPATH: ./ErrorHandler/AiHandleErrorAttribute.cs
using System;
using System.Text;
using Microsoft.ApplicationInsights;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace SLDBService.ErrorHandler
{

    public class AiHandleErrorAttribute : ExceptionFilterAttribute
    {
        private readonly IWebHostEnvironment _hostingEnvironment;
        private readonly TelemetryClient _telemetryClient;

        public AiHandleErrorAttribute(IWebHostEnvironment hostingEnvironment,
            TelemetryClient telemetryClient)
        {
            _hostingEnvironment = hostingEnvironment;
            _telemetryClient = telemetryClient;
        }

        public override void OnException(ExceptionContext filterContext)
        {
            if (filterContext != null && filterContext.HttpContext != null && filterContext.Exception != null)
            {
                //If this is any environment other than development, then AI HTTPModule will report the exception
                if ( _hostingEnvironment.EnvironmentName != Environments.Development )
                {
                    //Log request body using unicode encoding
                    var requestBody = filterContext.HttpContext.Request.Body;
                    var requestBodyString = new System.IO.StreamReader(requestBody,Encoding.Unicode).ReadToEnd();
                    _telemetryClient.TrackTrace("Unable to decode payload:" + requestBodyString);
                    _telemetryClient.TrackException(filterContext.Exception);
                }
            }

            base.OnException(filterContext);
        }
    }
}```

```csharp
// FILEPATH: ./Properties/AssemblyInfo.cs
using System.Reflection;
using System.Runtime.InteropServices;

// Allgemeine Informationen zu einer Assembly werden über die folgenden
// Attribute gesteuert. Ändern Sie diese Attributwerte, um die Informationen zu ändern,
// die mit einer Assembly verknüpft sind.
[assembly: AssemblyTitle("SLDBService")]
[assembly: AssemblyDescription("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("SLDBService")]
[assembly: AssemblyCopyright("Copyright © 2020")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// Durch Festlegen von "ComVisible" auf "false" werden die Typen in dieser Assembly unsichtbar
// für COM-Komponenten. Wenn Sie auf einen Typ in dieser Assembly aus
// COM zugreifen müssen, legen Sie das ComVisible-Attribut für diesen Typ auf "true" fest.
[assembly: ComVisible(false)]

// Die folgende GUID bestimmt die ID der "typelib", wenn dieses Projekt für COM verfügbar gemacht wird.
[assembly: Guid("24d938d9-5446-41c0-8b9e-c7dddea932cd")]

// Versionsinformationen für eine Assembly bestehen aus den folgenden vier Werten:
//
//      Hauptversion
//Nebenversion
//      Buildnummer
//      Revision
//
// Sie können alle Werte angeben oder die standardmäßigen Revisions- und Buildnummern
// übernehmen, indem Sie "*" eingeben:
[assembly: AssemblyVersion("0.3.0.0")]
[assembly: AssemblyFileVersion("0.3.0.0")]
```

```csharp
// FILEPATH: ./App_Start/SwaggerConfig.cs
using System.Collections.Generic;
using System.Reflection;
using System;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Swashbuckle.AspNetCore.SwaggerUI;
using Swashbuckle.AspNetCore.Swagger;
using Swashbuckle.AspNetCore.SwaggerGen;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using SLDBService;
using Microsoft.OpenApi.Models;
using Microsoft.OpenApi.Any;

namespace SLDBService
{
    public static class SwaggerConfig
    {
        private static readonly string API_NAME = $"SLDB Service v{Assembly.GetExecutingAssembly().GetName().Version.Major.ToString()}";

        public static void ConfigureServices(IServiceCollection services)
        {
            _ = services.AddSwaggerGen(c =>
              {
                // By default, the service root url is inferred from the request used to access the docs.
                // However, there may be situations (e.g. proxy and load-balanced environments) where this does not
                // resolve correctly. You can workaround this by providing your own code to determine the root URL.
                //
                //c.RootUrl(req => GetRootUrlFromAppConfig());

                // If schemes are not explicitly provided in a Swagger 2.0 document, then the scheme used to access
                // the docs is taken as the default. If your API supports multiple schemes and you want to be explicit
                // about them, you can use the "Schemes" option as shown below.
                //
                //c.Schemes(new[] { "http", "https" });

                // Use "SingleApiVersion" to describe a single version API. Swagger 2.0 includes an "Info" object to
                // hold additional metadata for an API. Version and title are required but you can also provide
                // additional fields by chaining methods off SingleApiVersion.
                //
                var major = Assembly.GetExecutingAssembly().GetName().Version.Major.ToString();
                  var minor = Assembly.GetExecutingAssembly().GetName().Version.Minor.ToString();


                  var info = new OpenApiInfo
                  {
                      Title = "SLDB Service",
                      Version = "v" + major + "_" + minor + "_0"
                  };
                  c.SwaggerDoc("v1", info);
                  c.OperationFilter<XSessionHeaderParameter>();

                // If you want the output Swagger docs to be indented properly, enable the "PrettyPrint" option.
                //
                //c.PrettyPrint();

                // If your API has multiple versions, use "MultipleApiVersions" instead of "SingleApiVersion".
                // In this case, you must provide a lambda that tells Swashbuckle which actions should be
                // included in the docs for a given API version. Like "SingleApiVersion", each call to "Version"
                // returns an "Info" builder so you can provide additional metadata per API version.
                //
                //c.MultipleApiVersions(
                //    (apiDesc, targetApiVersion) => ResolveVersionSupportByRouteConstraint(apiDesc, targetApiVersion),
                //    (vc) =>
                //    {
                //        vc.Version("v2", "Swashbuckle Dummy API V2");
                //        vc.Version("v1", "Swashbuckle Dummy API V1");
                //    });

                // You can use "BasicAuth", "ApiKey" or "OAuth2" options to describe security schemes for the API.
                // See https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md for more details.
                // NOTE: These only define the schemes and need to be coupled with a corresponding "security" property
                // at the document or operation level to indicate which schemes are required for an operation. To do this,
                // you'll need to implement a custom IDocumentFilter and/or IOperationFilter to set these properties
                // according to your specific authorization implementation
                //
                //c.BasicAuth("basic")
                //    .Description("Basic HTTP Authentication");
                //
                // NOTE: You must also configure 'EnableApiKeySupport' below in the SwaggerUI section
                //c.ApiKey("apiKey")
                //    .Description("API Key Authentication")
                //    .Name("apiKey")
                //    .In("header");
                //
                //c.OAuth2("oauth2")
                //    .Description("OAuth2 Implicit Grant")
                //    .Flow("implicit")
                //    .AuthorizationUrl("http://petstore.swagger.wordnik.com/api/oauth/dialog")
                //    //.TokenUrl("https://tempuri.org/token")
                //    .Scopes(scopes =>
                //    {
                //        scopes.Add("read", "Read access to protected resources");
                //        scopes.Add("write", "Write access to protected resources");
                //    });

                // Set this flag to omit descriptions for any actions decorated with the Obsolete attribute
                //c.IgnoreObsoleteActions();

                // Each operation be assigned one or more tags which are then used by consumers for various reasons.
                // For example, the swagger-ui groups operations according to the first tag of each operation.
                // By default, this will be controller name but you can use the "GroupActionsBy" option to
                // override with any value.
                //
                //c.GroupActionsBy(apiDesc => apiDesc.HttpMethod.ToString());

                // You can also specify a custom sort order for groups (as defined by "GroupActionsBy") to dictate
                // the order in which operations are listed. For example, if the default grouping is in place
                // (controller name) and you specify a descending alphabetic sort order, then actions from a
                // ProductsController will be listed before those from a CustomersController. This is typically
                // used to customize the order of groupings in the swagger-ui.
                //
                //c.OrderActionGroupsBy(new DescendingAlphabeticComparer());

                // If you annotate Controllers and API Types with
                // Xml comments (http://msdn.microsoft.com/en-us/library/b2s063f7(v=vs.110).aspx), you can incorporate
                // those comments into the generated docs and UI. You can enable this by providing the path to one or
                // more Xml comment files.
                //
                c.IncludeXmlComments(GetXmlCommentsPath());

                // Swashbuckle makes a best attempt at generating Swagger compliant JSON schemas for the various types
                // exposed in your API. However, there may be occasions when more control of the output is needed.
                // This is supported through the "MapType" and "SchemaFilter" options:
                //
                // Use the "MapType" option to override the Schema generation for a specific type.
                // It should be noted that the resulting Schema will be placed "inline" for any applicable Operations.
                // While Swagger 2.0 supports inline definitions for "all" Schema types, the swagger-ui tool does not.
                // It expects "complex" Schemas to be defined separately and referenced. For this reason, you should only
                // use the "MapType" option when the resulting Schema is a primitive or array type. If you need to alter a
                // complex Schema, use a Schema filter.
                //
                //c.MapType<ProductType>(() => new Schema { type = "integer", format = "int32" });

                // If you want to post-modify "complex" Schemas once they've been generated, across the board or for a
                // specific type, you can wire up one or more Schema filters.
                //
                //c.SchemaFilter<ApplySchemaVendorExtensions>();

                // In a Swagger 2.0 document, complex types are typically declared globally and referenced by unique
                // Schema Id. By default, Swashbuckle does NOT use the full type name in Schema Ids. In most cases, this
                // works well because it prevents the "implementation detail" of type namespaces from leaking into your
                // Swagger docs and UI. However, if you have multiple types in your API with the same class name, you'll
                // need to opt out of this behavior to avoid Schema Id conflicts.
                //
                //c.UseFullTypeNameInSchemaIds();

                // Alternatively, you can provide your own custom strategy for inferring SchemaId's for
                // describing "complex" types in your API.
                //
                //c.SchemaId(t => t.FullName.Contains('`') ? t.FullName.Substring(0, t.FullName.IndexOf('`')) : t.FullName);

                // Set this flag to omit schema property descriptions for any type properties decorated with the
                // Obsolete attribute
                //c.IgnoreObsoleteProperties();

                // In accordance with the built in JsonSerializer, Swashbuckle will, by default, describe enums as integers.
                // You can change the serializer behavior by configuring the StringToEnumConverter globally or for a given
                // enum type. Swashbuckle will honor this change out-of-the-box. However, if you use a different
                // approach to serialize enums as strings, you can also force Swashbuckle to describe them as strings.
                //
                //c.DescribeAllEnumsAsStrings();

                // Similar to Schema filters, Swashbuckle also supports Operation and Document filters:
                //
                // Post-modify Operation descriptions once they've been generated by wiring up one or more
                // Operation filters.
                //
                //c.OperationFilter<AddDefaultResponse>();
                //
                // If you've defined an OAuth2 flow as described above, you could use a custom filter
                // to inspect some attribute on each action and infer which (if any) OAuth2 scopes are required
                // to execute the operation
                //
                //c.OperationFilter<AssignOAuth2SecurityRequirements>();

                // Post-modify the entire Swagger document by wiring up one or more Document filters.
                // This gives full control to modify the final SwaggerDocument. You should have a good understanding of
                // the Swagger 2.0 spec. - https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md
                // before using this option.
                //
                //c.DocumentFilter<ApplyDocumentVendorExtensions>();

                // In contrast to WebApi, Swagger 2.0 does not include the query string component when mapping a URL
                // to an action. As a result, Swashbuckle will raise an exception if it encounters multiple actions
                // with the same path (sans query string) and HTTP method. You can workaround this by providing a
                // custom strategy to pick a winner or merge the descriptions for the purposes of the Swagger docs
                //
                //c.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());

                // Wrap the default SwaggerGenerator with additional behavior (e.g. caching) or provide an
                // alternative implementation for ISwaggerProvider with the CustomProvider option.
                //
                //c.CustomProvider((defaultProvider) => new CachingSwaggerProvider(defaultProvider));
            });

            // Opt-in to Newtonsoft support for Swagger (until project refrences to Newtonsoft are retired in favor of System.Text.Json)
            services.AddSwaggerGenNewtonsoftSupport();
        }

        public static void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.),
            app.UseSwaggerUI(c =>
            {
                        // Enable middleware to serve generated Swagger as a JSON endpoint.
                        app.UseSwagger();

                        // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.),
                        app.UseSwaggerUI(c =>
                        {
                            c.SwaggerEndpoint("/swagger/v1/swagger.json", API_NAME);
                        });

                        // Use the "DocumentTitle" option to change the Document title.
                        // Very helpful when you have multiple Swagger pages open, to tell them apart.
                        //
                        //c.DocumentTitle("My Swagger UI");

                        // Use the "InjectStylesheet" option to enrich the UI with one or more additional CSS stylesheets.
                        // The file must be included in your project as an "Embedded Resource", and then the resource's
                        // "Logical Name" is passed to the method as shown below.
                        //
                        //c.InjectStylesheet(containingAssembly, "Swashbuckle.Dummy.SwaggerExtensions.testStyles1.css");

                        // Use the "InjectJavaScript" option to invoke one or more custom JavaScripts after the swagger-ui
                        // has loaded. The file must be included in your project as an "Embedded Resource", and then the resource's
                        // "Logical Name" is passed to the method as shown above.
                        //
                        //c.InjectJavaScript(thisAssembly, "Swashbuckle.Dummy.SwaggerExtensions.testScript1.js");

                        // The swagger-ui renders boolean data types as a dropdown. By default, it provides "true" and "false"
                        // strings as the possible choices. You can use this option to change these to something else,
                        // for example 0 and 1.
                        //
                        //c.BooleanValues(new[] { "0", "1" });

                        // By default, swagger-ui will validate specs against swagger.io's online validator and display the result
                        // in a badge at the bottom of the page. Use these options to set a different validator URL or to disable the
                        // feature entirely.
                        //c.SetValidatorUrl("http://localhost/validator");
                        //c.DisableValidator();

                        // Use this option to control how the Operation listing is displayed.
                        // It can be set to "None" (default), "List" (shows operations for each resource),
                        // or "Full" (fully expanded: shows operations and their details).
                        //
                        //c.DocExpansion(DocExpansion.List);

                        // Specify which HTTP operations will have the 'Try it out!' option. An empty paramter list disables
                        // it for all operations.
                        //
                        //c.SupportedSubmitMethods("GET", "HEAD");

                        // Use the CustomAsset option to provide your own version of assets used in the swagger-ui.
                        // It's typically used to instruct Swashbuckle to return your version instead of the default
                        // when a request is made for "index.html". As with all custom content, the file must be included
                        // in your project as an "Embedded Resource", and then the resource's "Logical Name" is passed to
                        // the method as shown below.
                        //
                        //c.CustomAsset("index", containingAssembly, "YourWebApiProject.SwaggerExtensions.index.html");

                        // If your API has multiple versions and you've applied the MultipleApiVersions setting
                        // as described above, you can also enable a select box in the swagger-ui, that displays
                        // a discovery URL for each version. This provides a convenient way for users to browse documentation
                        // for different API versions.
                        //
                        //c.EnableDiscoveryUrlSelector();

                        // If your API supports the OAuth2 Implicit flow, and you've described it correctly, according to
                        // the Swagger 2.0 specification, you can enable UI support as shown below.
                        //
                        //c.EnableOAuth2Support(
                        //    clientId: "test-client-id",
                        //    clientSecret: null,
                        //    realm: "test-realm",
                        //    appName: "Swagger UI"
                        //    //additionalQueryStringParams: new Dictionary<string, string>() { { "foo", "bar" } }
                        //);

                        // If your API supports ApiKey, you can override the default values.
                        // "apiKeyIn" can either be "query" or "header"
                        //
                        //c.EnableApiKeySupport("apiKey", "header");
            });
        }

        private static string GetXmlCommentsPath()
        {
            var baseDirectory = AppContext.BaseDirectory;
            var commentsFileName = string.Format("{0}.XML", Assembly.GetExecutingAssembly().GetName().Name);
            var commentsFilePath = Path.Combine(baseDirectory, commentsFileName);

            return commentsFilePath;
        }

        public class XSessionHeaderParameter : IOperationFilter
        {


            public void Apply(OpenApiOperation operation, OperationFilterContext context)
            {

                var defaultValue = new OpenApiString("swagger");
                if (operation != null)
                {
                    if (operation.Parameters == null)
                        operation.Parameters = new List<OpenApiParameter>();

                    operation.Parameters.Add(new OpenApiParameter
                    {
                        Name = "X-SessionId",
                        Description = "Set a Session ID which is needed to identify the caller. The session id is generated by the authentication process.",
                        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                        Required = true,
                        Schema = new OpenApiSchema
                        {
                            Type = "string",
                            Default = defaultValue
                        }
                    });
                }
                
            }
        }

    }
}
```

```csharp
// FILEPATH: ./App_Start/FilterConfig.cs
using Microsoft.AspNetCore.Mvc.Filters;
using SLDBService.ErrorHandler;

namespace SLDBService
{
    public static class FilterConfig
    {
        public static void RegisterGlobalFilters(FilterCollection filters)
        {
            if(filters != null)
            {
                _ = filters.Add<AiHandleErrorAttribute>();//Use discard syntax if we do not use the return value.
            }
            
        }
    }
}
```

```csharp
// FILEPATH: ./Controllers/UrlHelperExtensions.cs
using System;
using Microsoft.AspNetCore.Mvc;

namespace SLDBService.Controllers
{
    public static class UrlHelperExtensions
    {
        
        public static IUrlHelper HttpsAware(this IUrlHelper helper)
        {
            if (!helper.ActionContext.HttpContext.Request.IsHttps)
            {
                helper.ActionContext.HttpContext.Request.Scheme = Uri.UriSchemeHttps;
                helper.ActionContext.HttpContext.Request.Host = new Microsoft.AspNetCore.Http.HostString(helper.ActionContext.HttpContext.Request.Host.Host, 443);
            }

            return helper;
        }
        
    }
}```

```csharp
// FILEPATH: ./Controllers/SLDBController.cs
using MediatR;
using Microsoft.ApplicationInsights;
using Microsoft.Extensions.Configuration;
using SLDBService.Models;
using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Net;
using System.Text;
using SLDBService.Util;
using System.Threading;

namespace SLDBService.Controllers
{
    /// <summary>
    /// HomeController provides api endpoints for SLDB service root and Home/Index.
    /// </summary>
    [ApiController]
    [Route("/")]
    public class HomeController : Microsoft.AspNetCore.Mvc.Controller
    {
        [HttpGet]
        [Route("", Name = "root")]
        public IActionResult Root()
        {
            return Ok("/");
        }
        [HttpGet]
        [Route("Home/Index", Name = "Index")]
        public IActionResult Index()
        {
            return Ok("Home/Index");
        }
        [HttpGet]
        [Route("logging", Name = "logging")]
        public IActionResult Logging()
        {
            if (SLDBConfiguration.EnableResponseLogging)
            {
                return Ok("Response logging is enabled");
            }
            else
            {
                return Ok("Response logging is disabled");
            }
        }
    }
    [ApiController]
    [Route("api/sldb")]
    public class SLDBController : Microsoft.AspNetCore.Mvc.Controller
    {
        /// <summary>
        /// Mediator
        /// </summary>
        public IMediator Mediator { get; }
        public IPlatformStorageAccess Storage { get; }
        public TelemetryClient Logger { get; }
        public ISLDBReset Sldbreset { get; set; }
        public IConfiguration Configuration { get; }

        /// <summary>
        /// Initializes new instance of controller with given <see cref="IMediator"/>
        /// </summary>
        /// <param name="mediator"></param>
        /// <param name="storage"></param>
        /// <param name="sldbreset"></param>
        /// <param name="logger"></param>
        /// <param name="configuration"></param>
        public SLDBController(IMediator mediator, IPlatformStorageAccess storage, ISLDBReset sldbreset, TelemetryClient logger, IConfiguration configuration)
        {
            Sldbreset = sldbreset;
            Mediator = mediator ?? throw new System.ArgumentNullException(nameof(mediator));
            Storage = storage ?? throw new ArgumentNullException(nameof(storage));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            Configuration = configuration;
            SLDBUtil.Init(logger);
        }

        private HttpResponseMessage CreateHttpMessage(HttpStatusCode statusCode, string content)
        {
            var response = new HttpResponseMessage(statusCode);
            response.Content = new StringContent(content);

            return response;
        }
        /// <summary>
        /// SLDB Base Data Version Check
        /// </summary>
        /// <returns></returns>
        [SwaggerResponse(StatusCodes.Status200OK, "BaseDataVersionCheckResponse", typeof(string))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Bad Request", typeof(string))]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Internal Error", typeof(string))]
        [SwaggerResponse(208, "Not found", typeof(string))]
        [HttpPost]
        [Route("{dbModelVersion}/version")]
        public async Task BaseDataVersionCheck([FromRoute] string dbModelVersion, [FromBody] BaseDataVersionCheckRequest request)
        {
            Response.ContentType = "application/json";
            if (request == null){
                Response.StatusCode = StatusCodes.Status208AlreadyReported;
                await Response.Body.WriteAsync(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(BadRequest("No request body sent.")))).ConfigureAwait(false);
                return;
            }


            try
            {
                var shouldReset = await Sldbreset.ShouldReset().ConfigureAwait(false);
                //Logger.TrackTrace($"SUCCESS: Data from PlatformStorage retrieved. ShouldReset == {shouldReset}");
            }
            catch (Exception ex)
            {
                Logger.TrackTrace($"ERROR: Exception occured trying to get data from platform storage: {ex.ToString()}");
            }

                request.CreateImageLink = MakeImageLinkDelegate();
                request.DbModelVersion = Version.Parse(dbModelVersion);
                /*if(Boolean.TryParse(Configuration.GetSection("AppSettings")["SkipBASDomain"],out bool skipBASDomain))
                {
                    request.SkipBASDomain = skipBASDomain;
                }
                else
                {
                    request.SkipBASDomain = true;
                }*/

                //Create new cancellation token
                using (var cancellationTokenSource =
                       new CancellationTokenSource(TimeSpan.FromSeconds(SLDBConfiguration.RequestTimeOutInSeconds)))
                {
                    var cancellationToken = cancellationTokenSource.Token;

                    try
                    {

                        var response = await Mediator.Send(request, cancellationToken).ConfigureAwait(false);

                        if (response.Status == ResultStatus.NotFound)
                        {
                            Response.StatusCode = StatusCodes.Status208AlreadyReported;
                            await Response.Body
                                .WriteAsync(Encoding.UTF8.GetBytes(
                                    JsonConvert.SerializeObject(StatusCode(StatusCodes.Status208AlreadyReported))))
                                .ConfigureAwait(false);
                            return;
                        }
                        else if (response.Status == ResultStatus.NotModified)
                        {
                            Response.StatusCode = StatusCodes.Status304NotModified;
                            await Response.Body
                                .WriteAsync(Encoding.UTF8.GetBytes(
                                    JsonConvert.SerializeObject(StatusCode(StatusCodes.Status304NotModified))))
                                .ConfigureAwait(false);
                            return;
                        }

                        var res = JsonConvert.SerializeObject(response, Formatting.None);

                        /*var stopWatch = System.Diagnostics.Stopwatch.StartNew();
        
                        stopWatch.Stop();
                        Logger.TrackTrace("Version check took :" + stopWatch.ElapsedMilliseconds + "ms");*/


                        Response.StatusCode = StatusCodes.Status200OK;
                        await Response.Body.WriteAsync(Encoding.UTF8.GetBytes(res)).ConfigureAwait(false);
                        //Logger.TrackTrace("Done");

                    }
                    catch (TaskCanceledException ex)
                    {
                        Response.StatusCode = StatusCodes.Status504GatewayTimeout;
                    }

                    catch (Exception ex)
                    {
                        throw;
                    }
                }

        }

        private CreateImageLinkDelegate MakeImageLinkDelegate()
        {
            if (Boolean.TryParse(Configuration.GetSection("AppSettings")["ImageLinkRouteOnly"], out bool routeOnly) && routeOnly)
            {
                return new CreateImageLinkDelegate((linkingId, logoId, version, format)
                        => Url.RouteUrl("LogoRoute", new Dictionary<string, object>
                        {
                            { "linkingId", linkingId },
                            { "logoId", logoId },
                            { "version", version },
                            { "format", format }
                        }));
            }
            else
            {
                // FIX: determine if this is the correct translation into .Net core
                return new CreateImageLinkDelegate((linkingId, logoId, version, format)
                        => Url.HttpsAware().Link("LogoRoute", new Dictionary<string, object>
                        {
                            { "linkingId", linkingId },
                            { "logoId", logoId },
                            { "version", version },
                            { "format", format }
                        }));
            }
        }

        // GET api/stationlogo/{stationId}/{version}/{format}
        [SwaggerResponse(StatusCodes.Status200OK, "Station logo", typeof(byte[]))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Not found", typeof(string))]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Internal Error", typeof(string))]
        [HttpGet]
        [Route("{dbModelVersion}/stationlogo/{linkingId}/{logoId}/{version}/{format}", Name = "LogoRoute")]
        public async Task<IActionResult> StationLogo([FromRoute] string dbModelVersion, int linkingId, int logoId,
            int version, int format)
        {
            using (var cancellationTokenSource =
                   new CancellationTokenSource(TimeSpan.FromSeconds(SLDBConfiguration.RequestTimeOutInSeconds)))
            {
                var cancellationToken = cancellationTokenSource.Token;
                try
                {

                    var response = await Mediator.Send(new StationLogoRequest
                    {
                        LinkingId = linkingId,
                        LogoId = logoId,
                        Format = format,
                        Version = version
                    },cancellationToken).ConfigureAwait(false);

                    if (response.Success)
                    {

                        var httpResponse = new FileContentResult(response.LogoData,
                            new Microsoft.Net.Http.Headers.MediaTypeHeaderValue("image/png"))
                        {
                            FileDownloadName = linkingId.ToString()
                        };

                        return httpResponse;
                    }
                    else
                    {
                        return NotFound("Logo not found");
                    }
                }
                catch(TaskCanceledException ex)
                { 
                    return StatusCode(StatusCodes.Status504GatewayTimeout);
                }
                catch (Exception)
                {
                    // No need to log exception, as this is already taken care of by LoggingBehavior in MediatR pipeline
                    throw;
                }
            }
            return NotFound("");
        }

        /// <summary>
        /// SLDB Reception Area Version Check
        /// </summary>
        /// <returns></returns>
        [SwaggerResponse(StatusCodes.Status200OK, "ReceptionAreaVersionCheckResponse", typeof(string))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Bad Request", typeof(string))]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Internal Error", typeof(string))]
        [HttpPost]
        [Route("{dbModelVersion}/versionReceptionArea")]
        public async Task<IActionResult> ReceptionAreaVersionCheck([FromRoute] string dbModelVersion,
            [FromBody] ReceptionAreaVersionCheckRequest request)
        {
            if (request == null) return BadRequest("No request body sent.");
            using (var cancellationTokenSource =
                   new CancellationTokenSource(TimeSpan.FromSeconds(SLDBConfiguration.RequestTimeOutInSeconds)))
            {
                var cancellationToken = cancellationTokenSource.Token;
                {
                    try
                    {
                        request.DbModelVersion = Version.Parse(dbModelVersion);

                        var response = await Mediator.Send(request,cancellationToken).ConfigureAwait(false);

                        if (response.Status == ResultStatus.NotFound)
                        {
                            return NotFound();
                        }
                        else if (response.Status == ResultStatus.NotModified)
                        {
                            return StatusCode(StatusCodes.Status304NotModified);
                        }

                        return Json(response);
                    }
                    catch (TaskCanceledException ex)
                    {
                        return StatusCode(StatusCodes.Status504GatewayTimeout);
                    }
                    catch (Exception)
                    {
                        // No need to log exception, as this is already taken care of by LoggingBehavior in MediatR pipeline
                        throw;
                    }
                }
            }
            return NotFound();
        }

        /// <summary>
        /// SLDB Mux Version Check
        /// </summary>
        /// <returns></returns>
        [SwaggerResponse(StatusCodes.Status200OK, "MuxVersionCheckResponse", typeof(string))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Bad Request", typeof(string))]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Internal Error", typeof(string))]
        [HttpPost]
        [Route("{dbModelVersion}/versionMux")]
        public async Task<IActionResult> MuxVersionCheck([FromRoute] string dbModelVersion, [FromBody] MuxVersionCheckRequest request)
        {
            using (var cancellationTokenSource =
                   new CancellationTokenSource(TimeSpan.FromSeconds(SLDBConfiguration.RequestTimeOutInSeconds)))
            {
                var cancellationToken = cancellationTokenSource.Token;
                if (request == null) return BadRequest("No request body sent.");
                try
                {
                    request.DbModelVersion = Version.Parse(dbModelVersion);

                    var response = await Mediator.Send(request,cancellationToken).ConfigureAwait(false);

                    if (response.Status == ResultStatus.NotFound)
                    {
                        return NotFound();
                    }
                    else if (response.Status == ResultStatus.NotModified)
                    {
                        return StatusCode(StatusCodes.Status304NotModified);
                    }

                    return Json(response);
                }
                catch(TaskCanceledException ex)
                {
                    return StatusCode(StatusCodes.Status504GatewayTimeout);
                }
                
                catch (Exception)
                {
                    // No need to log exception, as this is already taken care of by LoggingBehavior in MediatR pipeline
                    throw;
                }
            }

            return NotFound();
        }

        /// <summary>
        /// SLDB Unknown Station Check
        /// </summary>
        /// <returns></returns>
        [SwaggerResponse(StatusCodes.Status200OK, "UnknownStationResponse", typeof(string))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Bad Request", typeof(string))]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Internal Error", typeof(string))]
        [SwaggerResponse(208, "Already reported", typeof(string))]
        [HttpPost]
        [Route("{dbModelVersion}/unknown")]
        public async Task<IActionResult> UnknownStation([FromRoute] string dbModelVersion, [FromBody] UnknownStationRequest request)
        {
            using (var cancellationTokenSource =
                   new CancellationTokenSource(TimeSpan.FromSeconds(SLDBConfiguration.RequestTimeOutInSeconds)))
            {
                var cancellationToken = cancellationTokenSource.Token;
                try
                {
                    request.CreateImageLink = MakeImageLinkDelegate();
                    //Modify the lat long to round to configuired decimal places
                    request.LatRound = Math.Round(request.LatRound, SLDBConfiguration.GeoCoordinatePrecisionDigits);
                    request.LongRound = Math.Round(request.LongRound, SLDBConfiguration.GeoCoordinatePrecisionDigits);

                    var response = await Mediator.Send(request,cancellationToken).ConfigureAwait(false);

                    if (response.Status == ResultStatus.NotFound)
                    {
                        return StatusCode(StatusCodes.Status208AlreadyReported);
                    }

                    return Json(response);
                }
                catch(TaskCanceledException ex)
                {
                    
                    return StatusCode(StatusCodes.Status504GatewayTimeout);
                }
                
                catch (Exception ex)
                {
                    // No need to log exception, as this is already taken care of by LoggingBehavior in MediatR pipeline
                    throw;
                }
            }

            return NotFound();
        }

        /// <summary>
        /// SLDB Reset handling
        /// </summary>
        /// <returns></returns>
        [SwaggerResponse(StatusCodes.Status200OK, "SLDBResetResponse", typeof(string))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Bad Request", typeof(string))]
        [SwaggerResponse(StatusCodes.Status500InternalServerError, "Internal Error", typeof(string))]
        [SwaggerResponse(451, "Reset unconfirmed", typeof(string))]
        [HttpPost]
        [Route("{dbModelVersion}/reset")]
        public async Task<IActionResult> Reset([FromRoute] string dbModelVersion, [FromBody] ResetSldbRequest request)
        {
            
            if (request == null) return BadRequest("No request body sent.");

            if (dbModelVersion.ToLower() == "restart")
            {
                (Sldbreset as FakeSLDBReset).Restart();
                return Ok();
            }

            if (Guid.TryParse(dbModelVersion, out Guid sessionId))
            {
                (Sldbreset as FakeSLDBReset).SetSessionId(sessionId);
                return Ok();
            }

            var sessionIdString = this.Request.Headers["X-SessionId"].FirstOrDefault();
            if (sessionIdString != null && Guid.TryParse(sessionIdString, out Guid sessionIdHeader) && sessionIdHeader == (Sldbreset as FakeSLDBReset)._data.CurrentSessionId)
            {
                try
                {
                    var response = await Mediator.Send(request).ConfigureAwait(false);

                    if (response.Status == ResultStatus.Success)
                    {
                        return Ok();
                    }

                    return StatusCode(StatusCodes.Status451UnavailableForLegalReasons);
                }
                catch (Exception)
                {
                    // No need to log exception, as this is already taken care of by LoggingBehavior in MediatR pipeline
                    throw;
                }
            }

            return StatusCode(StatusCodes.Status451UnavailableForLegalReasons);
        }
    }
}```

```csharp
// FILEPATH: ./Data/JsonTypeHandler.cs
using Dapper;
using Newtonsoft.Json;
using System;
using System.Data;


namespace SLDBService.Data
{
    /// <summary>
    /// Dapper custom type handler that supports parsing JSON column values to entity objects.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class JsonTypeHandler<T> : SqlMapper.TypeHandler<T>
    {
        public override T Parse(object value)
        {
            if (value is string json && json != null)
            {
                return JsonConvert.DeserializeObject<T>(json);
            }

            return default(T);
        }

        public override void SetValue(IDbDataParameter parameter, T value)
        {
            throw new NotSupportedException("Metadata is read-only, so writing metadata is not supported.");
        }
    }
}```

```csharp
// FILEPATH: ./Data/DatabaseExtensions.cs
using System.Collections.Generic;
using System.Data;
using System.Dynamic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace SLDBService.Database
{
    public static class DatabaseExtensions
    {
        static MD5 md5 = MD5.Create();

        public static string CreateMD5(string clearText)
        {
            var bytes = Encoding.UTF8.GetBytes(clearText);
            var hash = md5.ComputeHash(bytes);
            var sb = new StringBuilder();
            sb.Append("0x");
            foreach (var byt in hash)
                sb.Append(byt.ToString("x2"));

            return sb.ToString();
        }

        //Wrapper for dapper's QueryAsync method with caching using concurrent dictionary
        public static async Task<IEnumerable<T>> QueryCachedUnknownStationsAsync<T>(this IDbConnection connection,
            string sql, object param, CancellationToken cancellationToken,IDbTransaction transaction = null, int? commandTimeout = null,
            CommandType? commandType = null)
        {
            if (SLDBConfiguration.CacheUnkownStations)
            {
                //Combine sql and param into a single string to form the key
                //Convert param to json string
                var paramJson = JsonConvert.SerializeObject(param); 
                var key = CreateMD5(sql + paramJson);
                
                var command = new CommandDefinition("SELECT colValue FROM unknownStationsCacheTable WHERE colKey = convert(bigint,convert(varbinary(16),@Key,1))",
                    new {Key = key}, cancellationToken: cancellationToken);
                var res = await connection.QueryAsync<string>(command).ConfigureAwait(false);
                if (res.Any())
                {
                    return JsonConvert.DeserializeObject<IEnumerable<T>>(res.First());
                }
                var sqlCommand = new CommandDefinition(sql,param,transaction,commandTimeout,commandType,cancellationToken: cancellationToken);

                var result = await connection.QueryAsync<T>(sqlCommand).ConfigureAwait(false);
                try
                {
                    var insertCommand = new CommandDefinition(
                        "INSERT  INTO unknownStationsCacheTable(colKey,colValue) values(convert(bigint,convert(varbinary(16),@Key,1)),@Value)",
                        new { key = key, value = JsonConvert.SerializeObject(result) },cancellationToken: cancellationToken);
                    await connection
                        .ExecuteAsync(
                            insertCommand).ConfigureAwait(false);
                }
                catch
                {
                }

                return result;
            }
            var commandDef = new CommandDefinition(sql, param, transaction, commandTimeout, commandType, cancellationToken: cancellationToken);

            return await connection.QueryAsync<T>(commandDef).ConfigureAwait(false);
        }

        //Wrapper for dapper's QueryAsync to new table called commonCacheTable
        public static async Task<IEnumerable<dynamic>> QueryCachedAsync(this IDbConnection connection,string sql,
            object param, CancellationToken cancellationToken,IDbTransaction transaction = null, int? commandTimeout = null,
            CommandType? commandType = null)
        {
            //Combine sql and param into a single string to form the key
            //Convert param to json string

            var paramJson = JsonConvert.SerializeObject(param);
            if (param is DynamicParameters)
            {
                var dynParam = param as DynamicParameters;
                foreach (var p in dynParam.ParameterNames)
                {
                    paramJson = paramJson.Replace($"{p}", $"{dynParam.Get<dynamic>(p)}");
                }
            }

            //SLDBUtil.Logger.TrackTrace($"QueryCachedTwoAsync >> {sql} >> {paramJson}");
            var key = CreateMD5(sql + paramJson);
            /*if(_sqlCache.ContainsKey(key)){
                return (IEnumerable<dynamic>)_sqlCache[key];
            }*/
            //SLDBUtil.Logger.TrackTrace($"QueryCachedAsync >> {sql} >> {paramJson} >> {key}");
            var command = new CommandDefinition("SELECT colValue FROM commonCacheTable WHERE colKey = convert(bigint,convert(varbinary(16),@Key,1))",
                new {Key = key}, cancellationToken: cancellationToken);
            var res = await connection.QueryAsync<string>(
                 command).ConfigureAwait(false);

            if (res.Any())
            {
                //_sqlCache[key] = JsonConvert.DeserializeObject<List<ExpandoObject>>(res.AsList()[0],new ExpandoObjectConverter());
                //Get the first element in the res


                return JsonConvert.DeserializeObject<List<ExpandoObject>>(res.First(), new ExpandoObjectConverter());
            }
            
            command = new CommandDefinition(sql, param, transaction, commandTimeout, commandType, cancellationToken: cancellationToken);

            var result = await connection.QueryAsync(command).ConfigureAwait(false);
            //_sqlCache[key] = result;
            try
            {
                var value = JsonConvert.SerializeObject(result,Formatting.None);
               
                var insertCommand = new CommandDefinition(
                    "INSERT  INTO commonCacheTable(colKey,colValue) values(convert(bigint,convert(varbinary(16),@Key,1)),@Value)",
                    new { key = key, value = JsonConvert.SerializeObject(result) }, cancellationToken: cancellationToken);
                await connection
                    .ExecuteAsync(
                        insertCommand).ConfigureAwait(false);
            }
            catch
            {
                //Ignore
            }

            return result;
        }
    }
}```

```csharp
// FILEPATH: ./Data/DataDomainTypeHandler.cs
using Dapper;
using System;
using System.Data;
using System.Linq;

namespace SLDBService.Data
{
    public class DataDomainTypeHandler : SqlMapper.TypeHandler<StatementMetadata.DataDomain>
    {
        public override StatementMetadata.DataDomain Parse(object value)
        {
            if (value is string enumValue && enumValue != null)
            {
                return (StatementMetadata.DataDomain)Enum.Parse(typeof(StatementMetadata.DataDomain), enumValue);
            }

            throw new FormatException($"Cannot parse '{value}' as Metadata.DataDomain.");
        }

        public override void SetValue(IDbDataParameter parameter, StatementMetadata.DataDomain value)
        {
            throw new NotSupportedException("Metadata is read-only, so writing metadata is not supported.");
        }
    }
}```

```csharp
// FILEPATH: ./Data/ReceptionAreaPolygonTypeHandler.cs
using Dapper;
using SLDBService.Services.UnknownStation;
using System;
using System.Data;
using System.Linq;

namespace SLDBService.Data
{
    public class ReceptionAreaPolygonTypeHandler : SqlMapper.TypeHandler<IReceptionAreaPolygon>
    {
        public override IReceptionAreaPolygon Parse(object value)
        {
            if (value is string stringValue && stringValue != null)
            {
                return ReceptionAreaPolygon.Create(stringValue);
            }

            throw new FormatException($"Cannot parse '{value}' as IReceptionAreaPolygon.");
        }

        public override void SetValue(IDbDataParameter parameter, IReceptionAreaPolygon value)
        {
            throw new NotSupportedException("ReceptionAreaPolygon is read-only, so writing polygon is not supported.");
        }
    }
}```

```csharp
// FILEPATH: ./Data/ParameterTypeHandler.cs
using Dapper;
using Newtonsoft.Json;
using SLDBService.StatementMetadata;
using System;
using System.Data;
using System.Linq;

namespace SLDBService.Data
{
    /// <summary>
    /// Dapper custom type handler that supports parsing JSON serialized parameter definitions to domain object.
    /// </summary>
    public class ParameterTypeHandler : SqlMapper.TypeHandler<StatementMetadata.StatementParameter[]>
    {
        public ParameterTypeHandler()
        {
        }

        public override StatementMetadata.StatementParameter[] Parse(object value)
        {
            if (value is string json && json != null)
            {
                var parameterDefinitions = JsonConvert.DeserializeObject<StatementMetadata.ParameterEntity[]>(json);

                return parameterDefinitions.Select(x => StatementMetadata.StatementParameter.CreateFrom(x)).ToArray();
            }

            throw new FormatException($"Cannot parse '{value}' as Metadata.Parameter[].");
        }

        public override void SetValue(IDbDataParameter parameter, StatementMetadata.StatementParameter[] value)
        {
            throw new NotSupportedException("Metadata is read-only, so writing metadata is not supported.");
        }
    }
}```

```csharp
// FILEPATH: ./Data/ConditionParameterTypeHandler.cs
using Dapper;
using Newtonsoft.Json;
using SLDBService.StatementMetadata;
using System;
using System.Data;
using System.Linq;

namespace SLDBService.Data
{
    /// <summary>
    /// Dapper custom type handler that supports parsing JSON serialized condition parameter definitions to domain object.
    /// </summary>
    public class ConditionParameterTypeHandler : SqlMapper.TypeHandler<StatementMetadata.ConditionParameter[]>
    {
        public ConditionParameterTypeHandler()
        {
        }

        public override StatementMetadata.ConditionParameter[] Parse(object value)
        {
            if (value is string json && !String.IsNullOrEmpty(json))
            {
                var parameterDefinitions = JsonConvert.DeserializeObject<StatementMetadata.ConditionParameterEntity[]>(json);

                return parameterDefinitions.Select(x => StatementMetadata.ConditionParameter.CreateFrom(x)).ToArray();
            }

            return new StatementMetadata.ConditionParameter[0];
        }

        public override void SetValue(IDbDataParameter parameter, StatementMetadata.ConditionParameter[] value)
        {
            throw new NotSupportedException("Metadata is read-only, so writing metadata is not supported.");
        }
    }
}```

```csharp
// FILEPATH: ./Data/SqlCommandTypeHandler.cs
using Dapper;
using System;
using System.Data;
using System.Linq;

namespace SLDBService.Data
{
    public class SqlCommandTypeHandler : SqlMapper.TypeHandler<StatementMetadata.SqlCommand>
    {
        public override StatementMetadata.SqlCommand Parse(object value)
        {
            if(value is string enumValue && enumValue != null)
            {
                return StatementMetadata.SqlCommands.Parse(enumValue);
            }

            throw new FormatException($"Cannot parse '{value}' as Metadata.SqlCommand.");
        }

        public override void SetValue(IDbDataParameter parameter, StatementMetadata.SqlCommand value)
        {
            throw new NotSupportedException("Metadata is read-only, so writing metadata is not supported.");
        }
    }
}```

```csharp
// FILEPATH: ./Data/SqlConnectionFactory.cs
using System;
using System.Data;
using System.Data.SqlClient;
using System.Linq;

namespace SLDBService.Data
{
    public class SqlConnectionFactory : IConnectionFactory
    {
        private readonly string _connectionString;

        public SqlConnectionFactory(string connectionString)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
        }

        public IDbConnection Create()
        {
            return new SqlConnection(_connectionString);
        }
    }
}```

```csharp
// FILEPATH: ./Data/CustomTypeHandlerRegistry.cs
using Dapper;
using SLDBService.StatementMetadata;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SLDBService.Data
{
    public class CustomTypeHandlerRegistry
    {
        public CustomTypeHandlerRegistry()
        {
        }

        public void Register()
        {
            // Dapper custom type handlers
            SqlMapper.AddTypeHandler(new ParameterTypeHandler());
            SqlMapper.AddTypeHandler(new ConditionParameterTypeHandler());
            SqlMapper.AddTypeHandler(new SqlCommandTypeHandler());
            SqlMapper.AddTypeHandler(new DataDomainTypeHandler());
            SqlMapper.AddTypeHandler(new ReceptionAreaPolygonTypeHandler());
        }
    }
}
```

```csharp
// FILEPATH: ./Data/IConnectionFactory.cs
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;

namespace SLDBService.Data
{
    /// <summary>
    /// Responsible for creating database connection objets.
    /// </summary>
    public interface IConnectionFactory
    {
        /// <summary>
        /// Creates and returns a database connection.
        /// </summary>
        /// <returns></returns>
        IDbConnection Create();
    }
}```

```csharp
// FILEPATH: ./Services/UnknownStation/IServiceTimeSharing.cs
using System;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SLDBService.Services.UnknownStation
{
    public interface IServiceTimeSharing
    {
        /// <summary>
        /// Checks whether the given <paramref name="candidates"/> do time sharing at the given <paramref name="timestamp"/> 
        /// and returns a single result, if the <paramref name="candidates"/> can be reduced to a single result.
        /// If <paramref name="candidates"/> are not time sharing or zero or more than one result is found, null will be returned.
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="timestamp"></param>
        /// <param name="candidates"></param>
        /// <returns></returns>
        Task<TimeSharingCandidate> Reduce(IDbConnection connection, DateTimeOffset timestamp, CancellationToken cancellationToken,params TimeSharingCandidate[] candidates);
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/UnknownStationRequestExtensions.cs
using SLDBService.Models;
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public static class UnknownStationRequestExtensions
    {
        public static string ONID(this UnknownStationRequest request) => request.ONID.ToString("X");
        public static string TSID(this UnknownStationRequest request) => request.EnsBouqTSId.ToString("X");
        public static string EID(this UnknownStationRequest request) => request.EnsBouqTSId.ToString("X");
        public static string ECC(this UnknownStationRequest request) => request.ECC.ToString("X");
        public static string SID(this UnknownStationRequest request) => request.StationId.ToString("X");
        public static int Frequency(this UnknownStationRequest request) => request.Frequency;
        public static double VPLatDeg(this UnknownStationRequest request) => request.LatRound;
        public static double VPLongDeg(this UnknownStationRequest request) => request.LongRound;
        public static string StationCallSign(this UnknownStationRequest request) => request.StationNameShort;
        public static Version DBModelVersion(this UnknownStationRequest request) => new Version(request.dBModelVersion, request.dBModelSubVersion);

        // Currently HU timestamp is sent in malformed format: eg.: "dt.Substring(0, 20) + dt.Substring(21, 2)"
        public static DateTimeOffset? GetTimestamp(this UnknownStationRequest request)
        {
            try
            {
                var ts = request.TimeStamp;
                if (!String.IsNullOrWhiteSpace(ts) && ts.Length >= 21 && ts.Substring(19, 2) == "::")
                {
                    // compensate bug in HU and remove one ":"
                    ts = ts.Substring(0, 20) + ts.Substring(21, 2);
                }
                if (DateTimeOffset.TryParse(ts, out DateTimeOffset result))
                {
                    return result;
                }
            }
            finally { }

            return null;
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/UnknownStationLookupResult.cs
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public class UnknownStationLookupResult
    {
        public bool Success => LinkingId != null;
        public int? LinkingId { get; }
        public int? MuxId { get; }
        public int? ReceptionAreaId { get; }
        public int? FrequencyId { get; }
        public int? TransmitterId { get; }
        public string Reason { get; }

        private UnknownStationLookupResult(int linkingId, int muxId, int receptionAreaId, int frequencyId, int transmitterId, string reason)
        {
            LinkingId = linkingId;
            MuxId = muxId;
            ReceptionAreaId = receptionAreaId;
            FrequencyId = frequencyId;
            TransmitterId = transmitterId;
            Reason = reason;
        }

        private UnknownStationLookupResult(string reason)
        {
            Reason = reason;
        }

        public static UnknownStationLookupResult Found(int linkingId, int muxId, int receptionAreaId, int frequencyId, int transmitterId, string reason = null)
            => new UnknownStationLookupResult(linkingId, muxId, receptionAreaId, frequencyId, transmitterId, reason);

        public static UnknownStationLookupResult NotFound(string reason)
            => new UnknownStationLookupResult(reason);
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ReceptionAreaPolygon.cs
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Models;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Dapper;

namespace SLDBService.Services.UnknownStation
{
    public static class ReceptionAreaPolygon
    {
        public static IReceptionAreaPolygon Create(string polygonDistancesHm)
        {
            // simple check to distinguish between angleDivisor == 1 and angleDivisor == 36
            if (polygonDistancesHm.Contains(','))
            {
                return new ReceptionAreaPolygonAngleDivisor36(polygonDistancesHm);
            }
            else
            {
                return new ReceptionAreaPolygonAngleDivisor1(polygonDistancesHm);
            }
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/IResolveUnknownStation.cs
using SLDBService.Models;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SLDBService.Services.UnknownStation
{
    public interface IResolveUnknownStation
    {
        int BroadcastingStandardNameId { get; }

        Task<UnknownStationLookupResult> Resolve(UnknownStationRequest request,CancellationToken cancellationToken);
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationDVB_T2.cs
using Microsoft.ApplicationInsights;
using SLDBService.Data;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationDVB_T2 : ResolveUnknownStationDVB_T
    {
        public override int BroadcastingStandardNameId => 5;

        public ResolveUnknownStationDVB_T2(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStation.cs
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public abstract class ResolveUnknownStation : IResolveUnknownStation
    {
        protected class ResultModel
        {
            public int linkingId { get; set; }
            public int receptionAreaId { get; set; }
            public int muxId { get; set; }
            public int frequencyId { get; set; }
            public int transmitterId { get; set; }
        }
        
        protected class ReceptionAreaModel
        {
            public int linkingId { get; set; }
            public int muxId { get; set; }
            public int receptionAreaId { get; set; }
            public int frequencyId { get; set; }
            public int transmitterId { get; set; }
            public int angleDivisor { get; set; }
            public IReceptionAreaPolygon receptionAreaPolygon { get; set; }
            public double MAXAreaMaxX { get; set; }
            public double MAXAreaMaxY { get; set; }
            public double MAXAreaMinX { get; set; }
            public double MAXAreaMinY { get; set; }
            public double VPLatRad { get; set; }
            public double VPLongRad { get; set; }
            public double TMLatRad { get; set; }
            public double TMLongRad { get; set; }
            public int DistanceHm { get; set; }
            public double BearingAngleDeg { get; set; }
            public bool IsInPolygonRectArea { get; set; }
            public string piCode { get; set; }
            public int frequency { get; set; }
        }

        public IConnectionFactory ConnectionFactory { get; }
        public IServiceTimeSharing ServiceTimeSharing { get; set; }
        public TelemetryClient Logger { get; }

        public abstract int BroadcastingStandardNameId { get; }

        protected ResolveUnknownStation(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
            ServiceTimeSharing = serviceTimeSharing ?? throw new ArgumentNullException(nameof(serviceTimeSharing));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<UnknownStationLookupResult> Resolve(UnknownStationRequest request,CancellationToken cancellationToken)
        {
            if (request.BroadcastStandard != BroadcastingStandardNameId)
            {
                throw new NotSupportedException($"The current unknown station resolver of type {GetType().Name} only supports broadcasting standard id {BroadcastingStandardNameId}. It does not support broadcasting standard {request.BroadcastStandard}");
            }

            using (var connection = ConnectionFactory.Create())
            {
                return await Resolve(connection, request,cancellationToken).ConfigureAwait(false);
            }
        }

        protected abstract Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken);

        protected async Task<IEnumerable<ResultModel>> ReduceByTimeSharing(IDbConnection connection, IEnumerable<ResultModel> models, DateTimeOffset? timestamp, CancellationToken cancellationToken)
        {
            if (timestamp != null)
            {
                var timeSharingInfo = models.Select(x => new TimeSharingCandidate(x.linkingId, x.muxId)).ToArray();
                var singleResult = await ServiceTimeSharing.Reduce(connection, timestamp.Value,cancellationToken, timeSharingInfo).ConfigureAwait(false);

                if (singleResult != null)
                {
                    return models.Where(x => x.linkingId == singleResult.LinkingId && x.muxId == singleResult.MuxId);
                }
            }

            return models;
        }
        
        protected async Task<IEnumerable<ReceptionAreaModel>> ReduceByTimeSharing(IDbConnection connection, IEnumerable<ReceptionAreaModel> models, DateTimeOffset? timestamp,CancellationToken cancellationToken)
        {
            if (timestamp != null)
            {
                var timeSharingInfo = models.Select(x => new TimeSharingCandidate(x.linkingId, x.muxId)).ToArray();
                var singleResult = await ServiceTimeSharing.Reduce(connection, timestamp.Value,cancellationToken, timeSharingInfo)
                    .ConfigureAwait(false);

                if (singleResult != null)
                {
                    return models.Where(x =>
                        x.linkingId == singleResult.LinkingId && x.muxId == singleResult.MuxId);
                }
            }

            return models;
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/Distances.cs
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public struct Distances
    {
        public DistanceAtAngle Distance1 { get; set; }
        public DistanceAtAngle Distance2 { get; set; }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ReceptionAreaPolygonAngleDivisor1.cs
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public class ReceptionAreaPolygonAngleDivisor1 : IReceptionAreaPolygon
    {
        public const int AngleDivisor = 1;
        public int PolygonDistanceHm { get; }

        public ReceptionAreaPolygonAngleDivisor1(string polygonDistanceHm)
        {
            PolygonDistanceHm = Int32.Parse(polygonDistanceHm);
        }

        public override bool Contains(int distanceValueHm)
        {
            return distanceValueHm <= PolygonDistanceHm;
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationDVB_T.cs
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationDVB_T : ResolveUnknownStation
    {
        private static class Reason
        {
            public const string DVBTnotfound2 = "DVBTnotfound2";
            public const string DVBTmultiple12 = "DVBTmultiple12";
            public const string DVBTnotfound33 = "DVBTnotfound33";
            public const string DVBTmultiple33 = "DVBTmultiple33";
        }

        private static class SqlQuery
        {
            // Parameters: @ONID, @TSID, @SID
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step1 =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId
                WHERE muxDef.OriginalNetworkId = @ONID AND muxDef.EnsembleId = @TSID AND  muxMap.piCode = @SID";

            // Parameters: @VPLatDeg, @VPLongDeg, @SID, @Frequency
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step2 =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                INNER JOIN frequencyTable freq ON freq.frequencyId = recMap.frequencyId
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxMap.piCode = @SID
                    AND freq.frequencyInKhz = @Frequency";

            // Parameters: @VPLatDeg, @VPLongDeg, @ONID, @TSID, @SID
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step3a =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxDef.OriginalNetworkId = @ONID AND muxDef.EnsembleId = @TSID AND  muxMap.piCode = @SID";

            // Parameters: @VPLatDeg, @VPLongDeg, @ONID, @TSID, @SID, @Frequency
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step3b =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                INNER JOIN frequencyTable freq ON freq.frequencyId = recMap.frequencyId
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxDef.OriginalNetworkId = @ONID AND muxDef.EnsembleId = @TSID AND muxMap.piCode = @SID
                    AND freq.frequencyInKhz = @Frequency";
        }

        public ResolveUnknownStationDVB_T(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }

        public override int BroadcastingStandardNameId => 4;

        protected override async Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationDVB_T.Resolve"))
            {
                var result = await QueryStep1(connection, request,cancellationToken).ConfigureAwait(false);
                result = result.DistinctBy(x => x.linkingId);
                // STEP 1 result count:
                // == 0 -> Step 2
                // == 1 -> EXIT
                // > 1 -> Step 3a
                var count = result.Count();
            
                if (count == 0)
                {
                    return await ExecuteStep2(connection, request,cancellationToken).ConfigureAwait(false);
                }
                else if (count == 1)
                {
                    var hit = result.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }
                else
                {
                    var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                    if (reducedCandidates.Count() == 1)
                    {
                        var hit = reducedCandidates.Single();

                        return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                    }

                    return await ExecuteStep3a(connection, request,cancellationToken).ConfigureAwait(false);
                }
            }
        }

        private async Task<UnknownStationLookupResult> ExecuteStep2(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            var result = await QueryStep2(connection, request, cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            // Step 2
            // == 0->DVBTnotfound2
            // == 1->EXIT
            //  > 1->DVBTmultiple12
            var count = result.Count();
            if (count == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.DVBTnotfound2);
            }
            else if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }
            else
            {
                var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var hit = reducedCandidates.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.DVBTmultiple12);
            }
        }

        private async Task<UnknownStationLookupResult> ExecuteStep3a(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            // Step 3a
            // == 0->Step 2
            // == 1->EXIT
            //  > 1->Step 3b
            var result = await QueryStep3a(connection, request,cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            var count = result.Count();
            if (count == 0)
            {
                return await ExecuteStep2(connection, request,cancellationToken).ConfigureAwait(false);
            }
            else if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }
            else
            {
                var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var hit = reducedCandidates.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                return await ExecuteStep3b(connection, request,cancellationToken).ConfigureAwait(false);
            }
        }

        private async Task<UnknownStationLookupResult> ExecuteStep3b(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            var result = await QueryStep3b(connection, request,cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            // Step 3b
            // == 0 -> DVBTnotfound33
            // == 1 -> EXIT
            //  > 1 -> DVBTmultiple33
            var count = result.Count();
            if (count == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.DVBTnotfound33);
            }
            else if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }
            else
            {
                var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var hit = reducedCandidates.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.DVBTmultiple33);
            }
        }


        private Task<IEnumerable<ResultModel>> QueryStep1(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step1,
                    new
                    {
                        ONID = request.ONID(),
                        TSID = request.TSID(),
                        SID = request.SID()
                    },cancellationToken);
        }

        private Task<IEnumerable<ResultModel>> QueryStep2(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken )
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step2,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        SID = request.SID(),
                        Frequency = request.Frequency()
                    },cancellationToken);
        }

        private Task<IEnumerable<ResultModel>> QueryStep3a(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step3a,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        ONID = request.ONID(),
                        TSID = request.TSID(),
                        SID = request.SID()
                    }, cancellationToken);
        }

        private Task<IEnumerable<ResultModel>> QueryStep3b(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step3b,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        ONID = request.ONID(),
                        TSID = request.TSID(),
                        SID = request.SID(),
                        Frequency = request.Frequency()
                    }, cancellationToken);
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ServiceTimeSharing.cs
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dapper;

namespace SLDBService.Services.UnknownStation
{
    public class ServiceTimeSharing : IServiceTimeSharing
    {
        private class TimeSharingResult
        {
            public int muxId { get; set; }
            public int linkingId { get; set; }
            public string startTime { get; set; }
            public string endTime { get; set; }
            public int Mon { get; set; }
            public int Tue { get; set; }
            public int Wed { get; set; }
            public int Thu { get; set; }
            public int Fri  { get; set; }
            public int Sat { get; set; }
            public int Sun { get; set; }

            public bool MatchesTimestamp(DateTimeOffset timestamp)
            {
                return MatchesDayOfWeek(timestamp) && MatchesTimeOfDay(timestamp);
            }

            private bool MatchesDayOfWeek(DateTimeOffset timestamp)
            {
                var dow = timestamp.DayOfWeek;
                switch (timestamp.DayOfWeek)
                {
                    case DayOfWeek.Monday:
                        return Mon == 1;

                    case DayOfWeek.Tuesday:
                        return Tue == 1;

                    case DayOfWeek.Wednesday:
                        return Wed == 1;

                    case DayOfWeek.Thursday:
                        return Thu == 1;

                    case DayOfWeek.Friday:
                        return Fri == 1;

                    case DayOfWeek.Saturday:
                        return Sat == 1;

                    case DayOfWeek.Sunday:
                        return Sun == 1;

                    default:
                        return false;
                }
            }

            private bool MatchesTimeOfDay(DateTimeOffset timestamp)
            {
                if (Int32.TryParse(startTime, out int start) && Int32.TryParse(endTime, out int end))
                {
                    var ts = timestamp.Hour * 100 + timestamp.Minute;

                    return ts >= start && ts > end;
                }

                return false;
            }
            
        }

        private const string SQL_QUERY = "SELECT * FROM serviceTimeSharingTable WHERE MuxId = (@MuxId)";

        public async Task<TimeSharingCandidate> Reduce(IDbConnection connection, DateTimeOffset timestamp, CancellationToken cancellationToken, params TimeSharingCandidate[] candidates)
        {
            // if there is only one candidate, return it as single result
            if (candidates.Length == 1)
            {
                return candidates.First();
            }
            if (candidates.Length == 0)
            {
                return null;
            }

            // if there are candidates with different MuxIds, we cannot reduce to a single result. TimeSharing is done on a single mux,
            // so we would always end up with more than one result.
            if (candidates.Select(x => x.MuxId).Distinct().Count() > 1)
            {
                return null;
            }
            else
            {
                // only one muxId among all candidates --> lookup time sharing table for more information
                var rows = await connection.QueryAsync<TimeSharingResult>(SQL_QUERY, new { MuxId = candidates.First().MuxId }).ConfigureAwait(false);

                // if there are no rows returned, services are not doing timesharing. 
                if (!rows.Any())
                {
                    return null;
                }
                else
                {
                    // services are timesharing --> see, if time sharing on this mux is done among all candidate linkingIds
                    var linkingIdsTimeSharing = rows.Select(x => x.linkingId);
                    if (candidates.Select(x => x.LinkingId).Except(linkingIdsTimeSharing).Any())
                    {
                        // not all candidate linkingIds are time sharing
                        return null;
                    }
                    else
                    {
                        // all candidate linkingIds are time sharing --> consider timestamp and see, if rows can be reduced to a single row
                        var matchingTimestamp = FindForTimestamp(rows, timestamp);
                        if (matchingTimestamp != null)
                        {
                            return new TimeSharingCandidate(matchingTimestamp.linkingId, matchingTimestamp.muxId);
                        }
                        else
                        {
                            return null;
                        }
                    }

                }
            }
        }

        private TimeSharingResult FindForTimestamp(IEnumerable<TimeSharingResult> rows, DateTimeOffset timestamp)
        {
            var ts = timestamp.ToUniversalTime();   // be sure to use utc

            var matchingTimestamp = rows.Where(x => x.MatchesTimestamp(ts));

            if (matchingTimestamp.Count() == 1)
            {
                return matchingTimestamp.Single();
            }

            return null;
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationFMnoPI.cs
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationFMnoPI : ResolveUnknownStation
    {
        private static class Reason
        {
            public const string piNotReceived = "piNotReceived";
            public const string FMnotfound2 = "FMnotfound2";
            public const string FMmultiple1 = "FMmultiple1";
            public const string FMmultiple2 = "FMmultiple2";
        }

        // Parameters: 
        // @VPLatDeg                : Vehicle position latitude in degrees
        // @VPLongDeg               : Vehicle position longitude in degrees
        // @Frequency               : Frequency of unknown station
        // @BroadcastingStandard    : Broadcasting standard
        // ReturnType: ReceptionAreaModel
        private const string sqlQueryReceptionAreas =
            @"SELECT 
                muxMappingTable.linkingId,
                muxMappingTable.muxId,
                recTable.receptionAreaId, 
                mappingTable.frequencyId,
                recTable.transmitterId,
                muxMappingTable.piCode,
                recTable.angleDivisor,
                recTable.receptionAreaPolygon,
                recTable.MAXAreaMaxX,
                recTable.MAXAreaMaxY,
                recTable.MAXAreaMinX,
                recTable.MAXAreaMinY,
                recTable.VPLatRad,
                recTable.VPLongRad,
                recTable.TMLatRad,
                recTable.TMLongRad, 
                recTable.IsInPolygonRectArea,
                ROUND(ACOS(COS(recTable.VPLatRad - recTable.TMLatRad) - COS(recTable.TMLatRad) * COS(recTable.VPLatRad) * (1 - COS(recTable.TMLongRad - recTable.VPLongRad))) * 63750, 0) AS DistanceHm,
                CAST(CAST(((ATN2(SIN(recTable.DiffLongRad) * COS(recTable.VPLatRad), COS(recTable.TMLatRad) * SIN(recTable.VPLatRad) - SIN(recTable.TMLatRad) * COS(recTable.VPLatRad) * COS(recTable.DiffLongRad)) * 180/PI()) + 360) AS decimal(38,19)) % 360 AS float) AS BearingAngleDeg
            FROM
                (SELECT 
                    *,
                    (@VPLatDeg) * PI()/180 AS VPLatRad, 
                    (@VPLongDeg) * PI()/180 AS VPLongRad, 
                    centerPosY * PI()/180 AS TMLatRad, 
                    centerPosX * PI()/180 AS TMLongRad,
                    ((@VPLongDeg) - centerPosX) * PI()/180 AS DiffLongRad,
		            CAST(CASE WHEN areaMinY <= (@VPLatDeg) AND areaMaxY >= (@VPLatDeg) AND areaMinX <= (@VPLongDeg) AND areaMaxX >= (@VPLongDeg) THEN 1 ELSE 0 END AS BIT) AS IsInPolygonRectArea
                FROM receptionAreaTable 
                WHERE (areaMinY <= (@VPLatDeg) AND areaMaxY >= (@VPLatDeg) AND areaMinX <= (@VPLongDeg) AND areaMaxX >= (@VPLongDeg))
                      OR (MAXAreaMinY <= (@VPLatDeg) AND MAXAreaMaxY >= (@VPLatDeg) AND MAXAreaMinX <= (@VPLongDeg) AND MAXAreaMaxX >= (@VPLongDeg))) recTable
            INNER JOIN receptionAreaToBroadcasterMappingTable mappingTable 
                ON mappingTable.receptionAreaId = recTable.receptionAreaId 
            INNER JOIN muxToServiceMappingTable muxMappingTable
                ON mappingTable.muxId = muxMappingTable.muxId
            WHERE mappingTable.frequencyId = 
                (SELECT frequencyId FROM frequencyTable 
                WHERE frequencyInKhz = (@Frequency) 
                    AND broadcastStandardNameId = @BroadcastingStandard)";

        public ResolveUnknownStationFMnoPI(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }

        public override int BroadcastingStandardNameId => 2;

        protected override async Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationFMnoPI.Resolve"))
            {
                using (var connectionOne = ConnectionFactory.Create())
                {
                    var recAreaCandidates =
                            await connectionOne.QueryCachedUnknownStationsAsync<ReceptionAreaModel>(
                            sqlQueryReceptionAreas,
                            new
                            {
                                VPLatDeg = request.LatRound,
                                VPLongDeg = request.LongRound,
                                Frequency = request.Frequency,
                                BroadcastingStandard = BroadcastingStandardNameId
                            },cancellationToken).ConfigureAwait(false);

                    // increase precision by looking at reception area polygon and vehicle position
                    var candidatesInRectangleEnclosingPolygon = recAreaCandidates.Where(x => x.IsInPolygonRectArea);
                    var finder = new PointInPolygonFinder();
                    var filteredCandidates = 
                        candidatesInRectangleEnclosingPolygon
                            .Where(x => finder.Contains(x.receptionAreaPolygon, x.DistanceHm, x.BearingAngleDeg))
                            .DistinctBy(x => x.linkingId);

                    int candidateCount = filteredCandidates.Count();
                    using (var connectionTwo = ConnectionFactory.Create())
                    {
                        if (candidateCount == 1)
                        {
                            var result = filteredCandidates.Single();
                            if (String.IsNullOrEmpty(result.piCode))
                            {
                                return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId);
                            }
                            else
                            {
                                // though SLDB has piCode for this station, no piCode was received from HU --> report with specific reason
                                return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId, Reason.piNotReceived);
                            }
                        }
                        else if (candidateCount == 0)
                        {
                            return await FindInMaxArea(connectionTwo, recAreaCandidates, request, cancellationToken).ConfigureAwait(false);
                        }
                        else
                        {
                            var reducedCandidates = await ReduceByTimeSharing(connectionTwo, filteredCandidates, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                            if (reducedCandidates.Count() == 1)
                            {
                                var result = reducedCandidates.Single();
                                return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId);
                            }

                            return UnknownStationLookupResult.NotFound(Reason.FMmultiple1);
                        }
                    }
                }
            }
        }

        private async Task<UnknownStationLookupResult> FindInMaxArea(IDbConnection connection,
            IEnumerable<ReceptionAreaModel> recAreaCandidates, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            var candidatesInMaxArea =
                recAreaCandidates
                    .Where(x => !x.IsInPolygonRectArea)
                    .DistinctBy(x => x.linkingId);

            var candidateMaxAreaCount = candidatesInMaxArea.Count();
            if (candidateMaxAreaCount == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.FMnotfound2);
            }
            else if (candidateMaxAreaCount == 1)
            {
                var hit = candidatesInMaxArea.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId,
                    hit.transmitterId);
            }
            else
            {
                var reducedCandidates =
                    await ReduceByTimeSharing(connection, candidatesInMaxArea, request.GetTimestamp(),cancellationToken)
                        .ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var result = reducedCandidates.Single();
                    return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId,
                        result.frequencyId, result.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.FMmultiple2);
            }
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/IReceptionAreaPolygon.cs
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public class  IReceptionAreaPolygon
    {
        /// <summary>
        /// If minimum of all distances of this polygon is greater than the given distanceValueHm, returns true, otherwise false.
        /// </summary>
        /// <param name="distanceValueHm"></param>
        /// <returns></returns>
        protected IReceptionAreaPolygon(){}
        public virtual bool Contains(int distanceValueHm){return false;}
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationISDBT.cs
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationISDBT : ResolveUnknownStation
    {
        private static class Reason
        {
            public const string ISDBTnotfound2 =  "ISDBTnotfound2";
            public const string ISDBTmultiple12 = "ISDBTmultiple12";
            public const string ISDBTnotfound33 = "ISDBTnotfound33";
            public const string ISDBTmultiple33 = "ISDBTmultiple33";
        }

        private static class SqlQuery
        {
            // Parameters: @TSID, @SID
            // Returns: { linkingId, muxId, receptionAreaId }
            public const string Step1 =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxMap.muxId = muxDef.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON recMap.muxId = muxMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId
                WHERE muxDef.EnsembleId = @TSID AND  muxMap.piCode = @SID";

            // Parameters: @VPLatDeg, @VPLongDeg, @SID, @Frequency
            // Returns: { linkingId, muxId, receptionAreaId }
            public const string Step2 =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                INNER JOIN frequencyTable freq ON freq.frequencyId = recMap.frequencyId
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxMap.piCode = @SID
                    AND freq.frequencyInKhz = @Frequency";

            // Parameters: @VPLatDeg, @VPLongDeg, @TSID, @SID
            // Returns: { linkingId, muxId, receptionAreaId }
            public const string Step3a =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxDef.EnsembleId = @TSID AND  muxMap.piCode = @SID";

            // Parameters: @VPLatDeg, @VPLongDeg, @TSID, @SID, @Frequency
            // Returns: { linkingId, muxId, receptionAreaId }
            public const string Step3b =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                INNER JOIN frequencyTable freq ON freq.frequencyId = recMap.frequencyId
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxDef.EnsembleId = @TSID AND muxMap.piCode = @SID
                    AND freq.frequencyInKhz = @Frequency";  
        }

        public ResolveUnknownStationISDBT(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }

        public override int BroadcastingStandardNameId => 6;

        protected override async Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationISDBT.Resolve"))
            {
                var result = await QueryStep1(connection, request,cancellationToken).ConfigureAwait(false);
                result = result.DistinctBy(x => x.linkingId);
                // STEP 1 result count:
                // == 0 -> Step 2
                // == 1 -> EXIT
                // > 1 -> Step 3a
                var count = result.Count();

                if (count == 0)
                {
                    return await ExecuteStep2(connection, request, cancellationToken).ConfigureAwait(false);
                }
                else if (count == 1)
                {
                    var hit = result.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }
                else
                {
                    var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                    if (reducedCandidates.Count() == 1)
                    {
                        var hit = reducedCandidates.Single();

                        return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                    }

                    return await ExecuteStep3a(connection, request,cancellationToken).ConfigureAwait(false);
                }
            }

        }

        private async Task<UnknownStationLookupResult> ExecuteStep2(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            var result = await QueryStep2(connection, request,cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            // Step 2
            // == 0->ISDBTnotfound2
            // == 1->EXIT
            //  > 1->ISDBTmultiple12
            var count = result.Count();
            if (count == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.ISDBTnotfound2);
            }
            else if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }
            else
            {
                var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var hit = reducedCandidates.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.ISDBTmultiple12);
            }
        }

        private async Task<UnknownStationLookupResult> ExecuteStep3a(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            // Step 3a
            // == 0->Step 2
            // == 1->EXIT
            //  > 1->Step 3b
            var result = await QueryStep3a(connection, request,cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            var count = result.Count();
            if (count == 0)
            {
                return await ExecuteStep2(connection, request, cancellationToken).ConfigureAwait(false);
            }
            else if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }
            else
            {
                var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var hit = reducedCandidates.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                return await ExecuteStep3b(connection, request,cancellationToken).ConfigureAwait(false);
            }
        }

        private async Task<UnknownStationLookupResult> ExecuteStep3b(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            var result = await QueryStep3b(connection, request,cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            // Step 3b
            // == 0 -> ISDBTnotfound33
            // == 1 -> EXIT
            //  > 1 -> ISDBTmultiple33
            var count = result.Count();
            if (count == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.ISDBTnotfound33);
            }
            else if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }
            else
            {
                var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var hit = reducedCandidates.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.ISDBTmultiple33);
            }
        }


        private Task<IEnumerable<ResultModel>> QueryStep1(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step1,
                    new
                    {
                        TSID = request.TSID(),
                        SID = request.SID()
                    },cancellationToken);
        }

        private Task<IEnumerable<ResultModel>> QueryStep2(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step2,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        SID = request.SID(),
                        Frequency = request.Frequency()
                    }, cancellationToken);
        }
        

        private Task<IEnumerable<ResultModel>> QueryStep3a(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step3a,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        TSID = request.TSID(),
                        SID = request.SID()
                    }, cancellationToken);
        }

        private Task<IEnumerable<ResultModel>> QueryStep3b(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step3b,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        TSID = request.TSID(),
                        SID = request.SID(),
                        Frequency = request.Frequency()
                    },
                    cancellationToken);
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/IFindLogoId.cs
using SLDBService.Data;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
namespace SLDBService.Services.UnknownStation
{
    public interface IFindLogoId
    {
        Task<int> Find(int linkingId, CancellationToken cancellationToken);
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/DistanceAtAngle.cs
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public struct DistanceAtAngle
    {
        public int DistanceHm { get; set; }
        public int Angle { get; set; }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationDAB.cs
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationDAB : ResolveUnknownStation
    {
        private static class Reason
        {
            public const string DABnotfound12 =  "DABnotfound12";
            public const string DABnotfound33 = "DABnotfound33";
            public const string DABnotfound34 = "DABnotfound34";
            public const string DABnotfound333 = "DABnotfound333";
            public const string DABmultiple34 = "DABmultiple34";
            public const string DABmultiple333 = "DABmultiple333";
        }

        private static class SqlQuery
        {
            // Parameters: @EID, @ECC, @SID
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step1 =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId
                WHERE muxDef.EnsembleId = @EID AND muxDef.EnsembleEcc = @ECC AND muxMap.piCode = @SID";

            // Parameters: @VPLatDeg, @VPLongDeg, @SID
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step2 =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxMap.piCode = @SID";

            // Parameters: @VPLatDeg, @VPLongDeg, @EID, @ECC, @SID
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step3a =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND  muxDef.EnsembleId = @EID AND muxDef.EnsembleEcc = @ECC AND  muxMap.piCode = @SID";

            // Parameters: @EID, @ECC, @SID, @Frequency
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step3b =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                INNER JOIN frequencyTable freq ON freq.frequencyId = recMap.frequencyId
                WHERE muxDef.EnsembleId = @EID AND muxDef.EnsembleEcc = @ECC AND  muxMap.piCode = @SID
                    AND freq.frequencyInKhz = @Frequency";

            // Parameters: @VPLatDeg, @VPLongDeg, @EID, @ECC, @SID, @Frequency
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step3c =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                INNER JOIN frequencyTable freq ON freq.frequencyId = recMap.frequencyId
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxDef.EnsembleId = @EID AND muxDef.EnsembleEcc = @ECC AND  muxMap.piCode = @SID
                    AND freq.frequencyInKhz = @Frequency";

            // Parameters: @VPLatDeg, @VPLongDeg, @SID, @Frequency
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step3d =
                @"SELECT 
                    muxMap.linkingId,
                    muxDef.muxId,
                    recMap.receptionAreaId,
                    recMap.frequencyId,
                    rec.transmitterId
                FROM muxDefinitionTable muxDef
                INNER JOIN muxToServiceMappingTable muxMap ON muxDef.muxId = muxMap.muxId
                INNER JOIN receptionAreaToBroadcasterMappingTable recMap ON muxDef.muxId = recMap.muxId
                INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId 
                INNER JOIN frequencyTable freq ON freq.frequencyId = recMap.frequencyId
                WHERE (rec.MAXAreaMinY <= @VPLatDeg AND rec.MAXAreaMaxY >= @VPLatDeg AND rec.MAXAreaMinX <= @VPLongDeg AND rec.MAXAreaMaxX >= @VPLongDeg) 
                    AND muxMap.piCode = @SID
                    AND freq.frequencyInKhz = @Frequency";
        }

        public ResolveUnknownStationDAB(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }

        public override int BroadcastingStandardNameId => 3;

        protected override async Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationDAB.Resolve"))
            {
                var result = await QueryStep1(connection, request,cancellationToken).ConfigureAwait(false);
                result = result.DistinctBy(x => x.linkingId);
                // STEP 1 result count:
                // == 0->Step 2
                // == 1->EXIT
                //  > 1->Step 3a
                var count = result.Count();

                if (count == 0)
                {
                    return await ExecuteStep2(connection, request,cancellationToken).ConfigureAwait(false);
                }

                if (count == 1)
                {
                    var hit = result.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var hit = reducedCandidates.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                return await ExecuteStep3a(connection, request,cancellationToken).ConfigureAwait(false);
            }

            
        }

        private async Task<UnknownStationLookupResult> ExecuteStep2(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            var result = await QueryStep2(connection, request, cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            // Step 2
            // == 0 -> DABnotfound12
            // == 1 -> EXIT
            //  > 1 -> Step 3d
            var count = result.Count();
            if (count == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.DABnotfound12);
            }

            if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
            if (reducedCandidates.Count() == 1)
            {
                var hit = reducedCandidates.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            return await ExecuteStep3d(connection, request,cancellationToken).ConfigureAwait(false);
        }

        private async Task<UnknownStationLookupResult> ExecuteStep3a(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            // Step 3a
            // == 0 -> Step 3b
            // == 1 -> EXIT
            //  > 1 -> Step 3b
            var result = await QueryStep3a(connection, request, cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            var count = result.Count();
            if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
            if (reducedCandidates.Count() == 1)
            {
                var hit = reducedCandidates.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            return await ExecuteStep3b(connection, request,cancellationToken).ConfigureAwait(false);
        }

        private async Task<UnknownStationLookupResult> ExecuteStep3b(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            var result = await QueryStep3b(connection, request, cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            // Step 3b
            // == 0 -> DABnotfound33
            // == 1 -> EXIT
            //  > 1 -> Step 3c
            var count = result.Count();
            if (count == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.DABnotfound33);
            }

            if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
            if (reducedCandidates.Count() == 1)
            {
                var hit = reducedCandidates.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            return await ExecuteStep3c(connection, request,cancellationToken).ConfigureAwait(false);
        }

        private async Task<UnknownStationLookupResult> ExecuteStep3c(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            var result = await QueryStep3c(connection, request, cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            // Step 3c
            // == 0 -> DABnotfound333
            // == 1 -> EXIT
            //  > 1 -> DABmultiple333
            var count = result.Count();
            if (count == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.DABnotfound333);
            }

            if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
            if (reducedCandidates.Count() == 1)
            {
                var hit = reducedCandidates.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            return UnknownStationLookupResult.NotFound(Reason.DABmultiple333);
        }

        private async Task<UnknownStationLookupResult> ExecuteStep3d(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            var result = await QueryStep3d(connection, request,cancellationToken).ConfigureAwait(false);
            result = result.DistinctBy(x => x.linkingId);
            // Step 3d
            // == 0 -> DABnotfound34
            // == 1 -> EXIT
            //  > 1 -> DABmultiple34
            var count = result.Count();
            if (count == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.DABnotfound34);
            }

            if (count == 1)
            {
                var hit = result.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
            if (reducedCandidates.Count() == 1)
            {
                var hit = reducedCandidates.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }

            return UnknownStationLookupResult.NotFound(Reason.DABmultiple34);
        }


        private Task<IEnumerable<ResultModel>> QueryStep1(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step1,
                    new
                    {
                        EID = request.EID(),
                        ECC = request.ECC(),
                        SID = request.SID()
                    },cancellationToken);
        }

        private Task<IEnumerable<ResultModel>> QueryStep2(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step2,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        SID = request.SID()
                    },cancellationToken);
        }

        private Task<IEnumerable<ResultModel>> QueryStep3a(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step3a,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        EID = request.EID(),
                        ECC = request.ECC(),
                        SID = request.SID()
                    },cancellationToken);
        }

        private Task<IEnumerable<ResultModel>> QueryStep3b(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step3b,
                    new
                    {
                        EID = request.EID(),
                        ECC = request.ECC(),
                        SID = request.SID(),
                        Frequency = request.Frequency()
                    },cancellationToken);
        }


        private Task<IEnumerable<ResultModel>> QueryStep3c(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step3c,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        EID = request.EID(),
                        ECC = request.ECC(),
                        SID = request.SID(),
                        Frequency = request.Frequency()
                    },cancellationToken);
        }


        private Task<IEnumerable<ResultModel>> QueryStep3d(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step3d,
                    new
                    {
                        VPLatDeg = request.VPLatDeg(),
                        VPLongDeg = request.VPLongDeg(),
                        SID = request.SID(),
                        Frequency = request.Frequency()
                    }, cancellationToken);
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationAM.cs
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    
    public class ResolveUnknownStationAM : ResolveUnknownStation
    {
        private static class Reason
        {
            public const string AMnotfound = "AMnotfound";
            public const string AMmultiple = "AMmultiple";
            public const string AMclosertx = "AMclosertx";
        }

        // Parameters: 
        // @VPLatDeg                : Vehicle position latitude in degrees
        // @VPLongDeg               : Vehicle position longitude in degrees
        // @Frequency               : Frequency of unknown station
        // @BroadcastingStandard    : 'AM' in this case
        // ReturnType: ReceptionAreaModel
        private const string sqlQueryReceptionAreas =
            @"SELECT 
                muxMappingTable.linkingId,
                muxMappingTable.muxId,
                recTable.receptionAreaId, 
                mappingTable.frequencyId,
                recTable.transmitterId,
                recTable.angleDivisor,
                recTable.receptionAreaPolygon,
                recTable.MAXAreaMaxX,
                recTable.MAXAreaMaxY,
                recTable.MAXAreaMinX,
                recTable.MAXAreaMinY,
                recTable.VPLatRad,
                recTable.VPLongRad,
                recTable.TMLatRad,
                recTable.TMLongRad, 
                recTable.IsInPolygonRectArea,
                ROUND(ACOS(COS(recTable.VPLatRad - recTable.TMLatRad) - COS(recTable.TMLatRad) * COS(recTable.VPLatRad) * (1 - COS(recTable.TMLongRad - recTable.VPLongRad))) * 63750, 0) AS DistanceHm,
                CAST(CAST(((ATN2(SIN(recTable.DiffLongRad) * COS(recTable.VPLatRad), COS(recTable.TMLatRad) * SIN(recTable.VPLatRad) - SIN(recTable.TMLatRad) * COS(recTable.VPLatRad) * COS(recTable.DiffLongRad)) * 180/PI()) + 360) AS decimal(38,19)) % 360 AS float) AS BearingAngleDeg
            FROM
                (SELECT 
                    *,
                    (@VPLatDeg) * PI()/180 AS VPLatRad, 
                    (@VPLongDeg) * PI()/180 AS VPLongRad, 
                    centerPosY * PI()/180 AS TMLatRad, 
                    centerPosX * PI()/180 AS TMLongRad,
                    ((@VPLongDeg) - centerPosX) * PI()/180 AS DiffLongRad,
		            CAST(CASE WHEN areaMinY <= (@VPLatDeg) AND areaMaxY >= (@VPLatDeg) AND areaMinX <= (@VPLongDeg) AND areaMaxX >= (@VPLongDeg) THEN 1 ELSE 0 END AS BIT) AS IsInPolygonRectArea
                FROM receptionAreaTable 
                WHERE (areaMinY <= (@VPLatDeg) AND areaMaxY >= (@VPLatDeg) AND areaMinX <= (@VPLongDeg) AND areaMaxX >= (@VPLongDeg))
                      OR (MAXAreaMinY <= (@VPLatDeg) AND MAXAreaMaxY >= (@VPLatDeg) AND MAXAreaMinX <= (@VPLongDeg) AND MAXAreaMaxX >= (@VPLongDeg))) recTable
            INNER JOIN receptionAreaToBroadcasterMappingTable mappingTable 
                ON mappingTable.receptionAreaId = recTable.receptionAreaId 
            INNER JOIN muxToServiceMappingTable muxMappingTable
                ON mappingTable.muxId = muxMappingTable.muxId
            WHERE mappingTable.frequencyId = 
                (SELECT frequencyId FROM frequencyTable 
                WHERE frequencyInKhz = (@Frequency) 
                    AND broadcastStandardNameId = @BroadcastingStandard)";

        public ResolveUnknownStationAM(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }

        public override int BroadcastingStandardNameId => 1;

        protected override async Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationAM.Resolve"))
            {
                var recAreaCandidates =
                    await connection.QueryCachedUnknownStationsAsync<ReceptionAreaModel>(
                        sqlQueryReceptionAreas,
                        new
                        {
                            VPLatDeg = request.LatRound,
                            VPLongDeg = request.LongRound,
                            Frequency = request.Frequency,
                            BroadcastingStandard = BroadcastingStandardNameId
                        },cancellationToken).ConfigureAwait(false);

                // increase precision by looking at reception area polygon and vehicle position
                var candidatesInRectangleEnclosingPolygon = recAreaCandidates.Where(x => x.IsInPolygonRectArea);
                var finder = new PointInPolygonFinder();
                var filteredCandidates =
                    candidatesInRectangleEnclosingPolygon
                        .Where(x => finder.Contains(x.receptionAreaPolygon, x.DistanceHm, x.BearingAngleDeg))
                        .DistinctBy(x => x.linkingId);

                int candidateCount = filteredCandidates.Count();
                if (candidateCount == 1) // if single result, after time sharing has been considered --> return; else use all candidates for further processing
                {
                    var result = filteredCandidates.Single();
                    return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId);
                }

                if (candidateCount == 2) 
                {
                    return await DeriveFromTransmitterDistances(connection, filteredCandidates.First(), filteredCandidates.Last(), request,cancellationToken).ConfigureAwait(false);
                }

                if (candidateCount == 0)
                {
                    return await FindInMaxArea(connection, recAreaCandidates, request,cancellationToken).ConfigureAwait(false);
                }

                var reducedCandidates = await ReduceByTimeSharing(connection, filteredCandidates, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var result = reducedCandidates.Single();
                    return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.AMmultiple);
            }
        }

        private async Task<UnknownStationLookupResult> FindInMaxArea(IDbConnection connection, IEnumerable<ReceptionAreaModel> recAreaCandidates, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationAM.FindInMaxArea"))
            {
                var candidatesInMaxArea = 
                    recAreaCandidates
                        .Where(x => !x.IsInPolygonRectArea)
                        .DistinctBy(x => x.linkingId);
            
                var candidateMaxAreaCount = candidatesInMaxArea.Count();
                if (candidateMaxAreaCount == 0)
                {
                    return UnknownStationLookupResult.NotFound(Reason.AMnotfound);
                }

                if (candidateMaxAreaCount == 1)
                {
                    var result = candidatesInMaxArea.Single();
                    return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId);
                }
                if (candidateMaxAreaCount == 2)
                {
                    return await DeriveFromTransmitterDistances(connection, candidatesInMaxArea.First(), candidatesInMaxArea.Last(), request,cancellationToken).ConfigureAwait(false);
                }
                var reducedCandidates = await ReduceByTimeSharing(connection, candidatesInMaxArea, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var result = reducedCandidates.Single();
                    return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.AMmultiple);
            }
        }

        private async Task<UnknownStationLookupResult> DeriveFromTransmitterDistances(IDbConnection connection, ReceptionAreaModel m1, ReceptionAreaModel m2, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationAM.DeriveFromTransmitterDistances"))
            {
                var d1 = m1.DistanceHm;
                var d2 = m2.DistanceHm;

                if (d1 < d2 && d1 / d2 < 0.1d)
                {
                    // m1 is very much closer than m2
                    return UnknownStationLookupResult.Found(m1.linkingId, m1.muxId, m1.receptionAreaId, m1.frequencyId,
                        m1.transmitterId, Reason.AMclosertx);
                }

                if (d2 > d1 && d2 / d1 < 0.1d)
                {
                    // m2 is very much closer than m1
                    return UnknownStationLookupResult.Found(m2.linkingId, m2.muxId, m2.receptionAreaId, m2.frequencyId,
                        m2.transmitterId, Reason.AMclosertx);
                }

                var reducedCandidates =
                    await ReduceByTimeSharing(connection, new ReceptionAreaModel[] {m1, m2}, request.GetTimestamp(),cancellationToken)
                        .ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var result = reducedCandidates.Single();
                    return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId,
                        result.frequencyId, result.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.AMmultiple);
            }
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/PointInPolygonFinder.cs
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public class PointInPolygonFinder
    {
        public PointInPolygonFinder()
        {
        }

        public bool Contains(IReceptionAreaPolygon polygon, int distanceHm, double bearingAngleDeg)
        {
            if (polygon.Contains(distanceHm))
            {
                return true;
            }

            if (polygon is ISupportBearingAngleDistances polygonExt)
            {
                var distances = polygonExt.GetDistancesForBearingAngle(bearingAngleDeg);

                var distanceAtBearingAngle =
                    distances.Distance1.DistanceHm - ((distances.Distance1.DistanceHm - distances.Distance2.DistanceHm / 10) * (bearingAngleDeg - distances.Distance1.Angle));

                return distanceHm <= distanceAtBearingAngle;
            }

            return false;
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/FindLogoId.cs
using SLDBService.Data;
using System;
using System.Threading;
using System.Threading.Tasks;
using Dapper;

namespace SLDBService.Services.UnknownStation
{
    public class FindLogoId : IFindLogoId
    {
        private const string QueryLogoId = "SELECT stationLogoId FROM serviceDataTable WHERE linkingId = @LinkingId";
        public IConnectionFactory ConnectionFactory { get; }
        public FindLogoId(IConnectionFactory connectionFactory)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        }

        public async Task<int> Find(int linkingId, CancellationToken cancellationToken)
        {
            using (var conn = ConnectionFactory.Create())
            {
                var command = new CommandDefinition(QueryLogoId, new { linkingId }, cancellationToken: cancellationToken);
                int result = await conn.ExecuteScalarAsync<int>(command).ConfigureAwait(false);
                return result;
            }
        }
    }
}

```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationFMPI.cs
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationFMPI : ResolveUnknownStation
    {
        public static class Reason
        {
            public const string FMnotfound12 = "FMnotfound12";
            public const string FMnotfound23 = "FMnotfound23";
            public const string FMmultiple13 = "FMmultiple13";
            public const string FMmultiple23 = "FMmultiple23";
        }

        // Parameters: 
        // @VPLatDeg                : Vehicle position latitude in degrees
        // @VPLongDeg               : Vehicle position longitude in degrees
        // @PICode                  : PICode (=StationId)
        // ReturnType: ReceptionAreaModel
        private const string sqlQueryReceptionAreasWithoutFrequency =
            @"SELECT 
                muxMappingTable.linkingId,
                muxMappingTable.muxId,
                recTable.receptionAreaId, 
                recTable.transmitterId,
                muxMappingTable.piCode,
                mappingTable.frequencyId,
                recTable.angleDivisor,
                recTable.receptionAreaPolygon,
                recTable.MAXAreaMaxX,
                recTable.MAXAreaMaxY,
                recTable.MAXAreaMinX,
                recTable.MAXAreaMinY,
                recTable.VPLatRad,
                recTable.VPLongRad,
                recTable.TMLatRad,
                recTable.TMLongRad, 
                recTable.IsInPolygonRectArea,
                ROUND(ACOS(COS(recTable.VPLatRad - recTable.TMLatRad) - COS(recTable.TMLatRad) * COS(recTable.VPLatRad) * (1 - COS(recTable.TMLongRad - recTable.VPLongRad))) * 63750, 0) AS DistanceHm,
                CAST(CAST(((ATN2(SIN(recTable.DiffLongRad) * COS(recTable.VPLatRad), COS(recTable.TMLatRad) * SIN(recTable.VPLatRad) - SIN(recTable.TMLatRad) * COS(recTable.VPLatRad) * COS(recTable.DiffLongRad)) * 180/PI()) + 360) AS decimal(38,19)) % 360 AS float) AS BearingAngleDeg
            FROM
                (SELECT 
                    *,
                    (@VPLatDeg) * PI()/180 AS VPLatRad, 
                    (@VPLongDeg) * PI()/180 AS VPLongRad, 
                    centerPosY * PI()/180 AS TMLatRad, 
                    centerPosX * PI()/180 AS TMLongRad,
                    ((@VPLongDeg) - centerPosX) * PI()/180 AS DiffLongRad,
		            CAST(CASE WHEN areaMinY <= (@VPLatDeg) AND areaMaxY >= (@VPLatDeg) AND areaMinX <= (@VPLongDeg) AND areaMaxX >= (@VPLongDeg) THEN 1 ELSE 0 END AS BIT) AS IsInPolygonRectArea
                FROM receptionAreaTable 
                WHERE (areaMinY <= (@VPLatDeg) AND areaMaxY >= (@VPLatDeg) AND areaMinX <= (@VPLongDeg) AND areaMaxX >= (@VPLongDeg))
                      OR (MAXAreaMinY <= (@VPLatDeg) AND MAXAreaMaxY >= (@VPLatDeg) AND MAXAreaMinX <= (@VPLongDeg) AND MAXAreaMaxX >= (@VPLongDeg))) recTable
            INNER JOIN receptionAreaToBroadcasterMappingTable mappingTable 
                ON mappingTable.receptionAreaId = recTable.receptionAreaId 
            INNER JOIN muxToServiceMappingTable muxMappingTable
                ON mappingTable.muxId = muxMappingTable.muxId
            WHERE muxMappingTable.piCode = (@PICode)";

        // Parameters: 
        // @VPLatDeg                : Vehicle position latitude in degrees
        // @VPLongDeg               : Vehicle position longitude in degrees
        // @Frequency               : Frequency
        // @BroadcastingStandard    : Broadcasting standard
        // @PICode                  : PICode (=StationId)
        // ReturnType: ReceptionAreaModel
        private const string sqlQueryReceptionAreasWithFrequency =
            @"SELECT 
                muxMappingTable.linkingId,
                muxMappingTable.muxId,
                recTable.receptionAreaId, 
                mappingTable.frequencyId,
                recTable.transmitterId,
                muxMappingTable.piCode,
                recTable.angleDivisor,
                recTable.receptionAreaPolygon,
                recTable.MAXAreaMaxX,
                recTable.MAXAreaMaxY,
                recTable.MAXAreaMinX,
                recTable.MAXAreaMinY,
                recTable.VPLatRad,
                recTable.VPLongRad,
                recTable.TMLatRad,
                recTable.TMLongRad, 
                recTable.IsInPolygonRectArea,
                ROUND(ACOS(COS(recTable.VPLatRad - recTable.TMLatRad) - COS(recTable.TMLatRad) * COS(recTable.VPLatRad) * (1 - COS(recTable.TMLongRad - recTable.VPLongRad))) * 63750, 0) AS DistanceHm,
                CAST(CAST(((ATN2(SIN(recTable.DiffLongRad) * COS(recTable.VPLatRad), COS(recTable.TMLatRad) * SIN(recTable.VPLatRad) - SIN(recTable.TMLatRad) * COS(recTable.VPLatRad) * COS(recTable.DiffLongRad)) * 180/PI()) + 360) AS decimal(38,19)) % 360 AS float) AS BearingAngleDeg
            FROM
                (SELECT 
                    *,
                    (@VPLatDeg) * PI()/180 AS VPLatRad, 
                    (@VPLongDeg) * PI()/180 AS VPLongRad, 
                    centerPosY * PI()/180 AS TMLatRad, 
                    centerPosX * PI()/180 AS TMLongRad,
                    ((@VPLongDeg) - centerPosX) * PI()/180 AS DiffLongRad,
		            CAST(CASE WHEN areaMinY <= (@VPLatDeg) AND areaMaxY >= (@VPLatDeg) AND areaMinX <= (@VPLongDeg) AND areaMaxX >= (@VPLongDeg) THEN 1 ELSE 0 END AS BIT) AS IsInPolygonRectArea
                FROM receptionAreaTable 
                WHERE (areaMinY <= (@VPLatDeg) AND areaMaxY >= (@VPLatDeg) AND areaMinX <= (@VPLongDeg) AND areaMaxX >= (@VPLongDeg))
                      OR (MAXAreaMinY <= (@VPLatDeg) AND MAXAreaMaxY >= (@VPLatDeg) AND MAXAreaMinX <= (@VPLongDeg) AND MAXAreaMaxX >= (@VPLongDeg))) recTable
            INNER JOIN receptionAreaToBroadcasterMappingTable mappingTable 
                ON mappingTable.receptionAreaId = recTable.receptionAreaId 
            INNER JOIN muxToServiceMappingTable muxMappingTable
                ON mappingTable.muxId = muxMappingTable.muxId
            WHERE (mappingTable.frequencyId = 
                (SELECT frequencyId FROM frequencyTable 
                WHERE frequencyInKhz = (@Frequency) 
                    AND broadcastStandardNameId = @BroadcastingStandard)
                    AND muxMappingTable.piCode = (@PICode))";

        public ResolveUnknownStationFMPI(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }

        public override int BroadcastingStandardNameId => 2;

        protected override async Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationFMPI.Resolve"))
            {
                using (var connectionOne = ConnectionFactory.Create())
                {
                    var piCode = request.StationId.ToString("X");
                    var frequency = request.Frequency;

                    var recAreaCandidatesWithoutFrequency =
                            await connectionOne.QueryCachedUnknownStationsAsync<ReceptionAreaModel>(
                            sqlQueryReceptionAreasWithoutFrequency,
                            new
                            {
                                VPLatDeg = request.LatRound,
                                VPLongDeg = request.LongRound,
                                PICode = piCode
                            },cancellationToken).ConfigureAwait(false);
                    using (var connectionTwo = ConnectionFactory.Create())
                    {
                        var recAreaCandidatesWithFrequency =
                            await connectionTwo.QueryCachedUnknownStationsAsync<ReceptionAreaModel>(
                        sqlQueryReceptionAreasWithFrequency,
                        new
                        {
                            VPLatDeg = request.LatRound,
                            VPLongDeg = request.LongRound,
                            BroadcastingStandard = BroadcastingStandardNameId,
                            Frequency = frequency,
                            PICode = piCode
                        },cancellationToken).ConfigureAwait(false);


                        // look at reception area polygon, vehicle position and piCode
                        var candidatesInRectangleEnclosingPolygon = recAreaCandidatesWithoutFrequency.Where(x => x.IsInPolygonRectArea);
                        var finder = new PointInPolygonFinder();
                        var filteredCandidates = 
                            candidatesInRectangleEnclosingPolygon
                                .Where(x => finder.Contains(x.receptionAreaPolygon, x.DistanceHm, x.BearingAngleDeg))
                                .DistinctBy(x => x.linkingId);

                        using (var connectionThree = ConnectionFactory.Create())
                        {
                            int candidateCount = filteredCandidates.Count();
                            if (candidateCount == 1)
                            {
                                var hit = filteredCandidates.Single();

                                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                            }
                            else if (candidateCount == 0)
                            {
                                var maxAreaResultWithoutFrequency = FindInMaxArea(recAreaCandidatesWithoutFrequency);
                                if (maxAreaResultWithoutFrequency == null)
                                {
                                    // search with frequency

                                    return await FindInMaxAreaRespectFrequency(connectionThree, recAreaCandidatesWithFrequency, request,cancellationToken).ConfigureAwait(false);
                                }
                                else
                                {
                                    return maxAreaResultWithoutFrequency;
                                }
                            }
                            else
                            {
                                // search with frequency

                                var candidatesInRectangleEnclosingPolygonWithFrequency = recAreaCandidatesWithFrequency.Where(x => x.IsInPolygonRectArea);
                                var filteredCandidatesWithFrequency = 
                                    candidatesInRectangleEnclosingPolygonWithFrequency
                                        .Where(x => finder.Contains(x.receptionAreaPolygon, x.DistanceHm, x.BearingAngleDeg))
                                        .DistinctBy(x => x.linkingId);

                                candidateCount = filteredCandidatesWithFrequency.Count();
                                if (candidateCount == 1)
                                {
                                    var hit = filteredCandidatesWithFrequency.Single();

                                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                                }
                                else if (candidateCount == 0)
                                {
                                    return await FindInMaxAreaRespectFrequency(connectionThree, recAreaCandidatesWithFrequency, request, cancellationToken).ConfigureAwait(false);
                                }
                                else
                                {
                                    var reducedCandidates = await ReduceByTimeSharing(connectionThree, filteredCandidatesWithFrequency, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                                    if (reducedCandidates.Count() == 1)
                                    {
                                        var result = reducedCandidates.Single();
                                        return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId);
                                    }

                                    return UnknownStationLookupResult.NotFound(Reason.FMmultiple13);
                                }
                            }
                        }
                    }
                }
            }

        }

        private UnknownStationLookupResult FindInMaxArea(IEnumerable<ReceptionAreaModel> recAreaCandidates)
        {
            var candidatesInMaxArea = 
                recAreaCandidates
                .Where(x => !x.IsInPolygonRectArea)
                .DistinctBy(x => x.linkingId);

            var candidateMaxAreaCount = candidatesInMaxArea.Count();
            if (candidateMaxAreaCount == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.FMnotfound12);
            }
            else if (candidateMaxAreaCount == 1)
            {
                var hit = candidatesInMaxArea.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }
            else
            {
                return null;
            }
        }

        private async Task<UnknownStationLookupResult> FindInMaxAreaRespectFrequency(IDbConnection connection, IEnumerable<ReceptionAreaModel> recAreaCandidates, UnknownStationRequest request, CancellationToken cancellationToken)
        {
            var candidatesInMaxArea = 
                recAreaCandidates
                    .Where(x => !x.IsInPolygonRectArea)
                    .DistinctBy(x => x.linkingId);

            var candidateMaxAreaCount = candidatesInMaxArea.Count();
            if (candidateMaxAreaCount == 0)
            {
                return UnknownStationLookupResult.NotFound(Reason.FMnotfound23);
            }
            else if (candidateMaxAreaCount == 1)
            {
                var hit = candidatesInMaxArea.Single();

                return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
            }
            else
            {
                var reducedCandidates = await ReduceByTimeSharing(connection, candidatesInMaxArea, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var result = reducedCandidates.Single();
                    return UnknownStationLookupResult.Found(result.linkingId, result.muxId, result.receptionAreaId, result.frequencyId, result.transmitterId);
                }

                return UnknownStationLookupResult.NotFound(Reason.FMmultiple23);
            }
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationHD_AM.cs
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationHD_AM : ResolveUnknownStation
    {
        private static class SqlQuery
        {
            // Parameters: @Frequency, @BroadcastingStandardId, @StationCallSign, @SubchannelId
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step1 =
                @"SELECT 
	                muxMap.linkingId,
	                recMap.muxId,
	                recMap.receptionAreaId,
	                recMap.frequencyId,
	                rec.transmitterId
                  FROM receptionAreaToBroadcasterMappingTable recMap
                  INNER JOIN muxToServiceMappingTable muxMap ON muxMap.muxId = recMap.muxId
                  INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId
                  WHERE recMap.frequencyId = (SELECT frequencyId FROM frequencyTable WHERE frequencyInKhz = @Frequency AND broadcastStandardNameId = @broadcastingStandardId)
                  AND recMap.stationCallSign = @StationCallSign
                  AND muxMap.subchannelId = @SubchannelId";
        }

        public ResolveUnknownStationHD_AM(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }

        public override int BroadcastingStandardNameId => 8;

        protected override async Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationHD_AM.Resolve"))
            {
                var result = await QueryStep1(connection, request,cancellationToken).ConfigureAwait(false);
                result = result.DistinctBy(x => x.linkingId);
                // STEP 1 result count:
                // != 1->NotFound
                // == 1->EXIT
                var count = result.Count();

                if (count == 1)
                {
                    var hit = result.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }
                else
                {
                    var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                    if (reducedCandidates.Count() == 1)
                    {
                        var hit = reducedCandidates.Single();

                        return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                    }

                    return UnknownStationLookupResult.NotFound("HDAMnotfound");
                }
            }

        }

        private Task<IEnumerable<ResultModel>> QueryStep1(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step1,
                    new
                    {
                        Frequency = request.Frequency(),
                        BroadcastingStandardId = request.BroadcastStandard,
                        SubchannelId = request.SubchannelID,
                        StationCallSign = request.StationCallSign()
                    },cancellationToken);
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/TimeSharingCandidate.cs
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public class TimeSharingCandidate
    {
        public TimeSharingCandidate(int linkingId, int muxId)
        {
            LinkingId = linkingId;
            MuxId = muxId;
        }

        public int LinkingId { get; }
        public int MuxId { get; }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationFM.cs
using System;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationFM : IResolveUnknownStation
    {
        public static class Reason
        {
            public const string piNotOnSLDB = "piNotOnSLDB";
        }

        public IConnectionFactory ConnectionFactory { get; }
        public IServiceTimeSharing ServiceTimeSharing { get; set; }
        public TelemetryClient Logger { get; }

        public int BroadcastingStandardNameId => 2;

        public ResolveUnknownStationFM(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
        {
            ConnectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
            ServiceTimeSharing = serviceTimeSharing ?? throw new ArgumentNullException(nameof(serviceTimeSharing));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<UnknownStationLookupResult> Resolve(UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationFM.Resolve"))
            {
                if (request.BroadcastStandard != BroadcastingStandardNameId)
                {
                    throw new NotSupportedException(
                        $"The current unknown station resolver of type {GetType().Name} only supports broadcasting standard id {BroadcastingStandardNameId}. It does not support broadcasting standard {request.BroadcastStandard}");
                }

                // Initial decision: 
                //  If StationID (=PICode) == 0 or empty --> use FMnoPI algorithm --> if PICode in SLDB result set, then report piNotReceived
                //  If StationID != 0 --> if PICode in SLDB result set --> use FMwithPI algorithm, else use FMnoPI algorithm and report piNotOnSLDB

                var piCode = request.StationId;
                if (piCode == 0)
                {
                    // use FMnoPI algorithm
                    var fmNoPI = new ResolveUnknownStationFMnoPI(ConnectionFactory, ServiceTimeSharing, Logger);

                    return await fmNoPI.Resolve(request,cancellationToken).ConfigureAwait(false);
                }

                // use either FMnoPI or FMPI algorithm
                // start with FMPI algorithm and decide on its result whether to use FMnoPI
                var fmPI = new ResolveUnknownStationFMPI(ConnectionFactory, ServiceTimeSharing, Logger);

                var resultFMPI = await fmPI.Resolve(request,cancellationToken).ConfigureAwait(false);

                if (resultFMPI.Reason == ResolveUnknownStationFMPI.Reason.FMnotfound12 ||
                    resultFMPI.Reason == ResolveUnknownStationFMPI.Reason.FMnotfound23)
                {
                    // switch to FMnoPI
                    var fmNoPI = new ResolveUnknownStationFMnoPI(ConnectionFactory, ServiceTimeSharing, Logger);

                    var resultFMnoPI = await fmNoPI.Resolve(request,cancellationToken).ConfigureAwait(false);
                    if (resultFMnoPI.Success)
                    {
                        // can return result of FMnoPI, but must include reason for later analysis
                        return UnknownStationLookupResult.Found(resultFMnoPI.LinkingId.Value,
                            resultFMnoPI.MuxId.Value, resultFMnoPI.ReceptionAreaId.Value,
                            resultFMnoPI.FrequencyId.Value, resultFMnoPI.TransmitterId.Value, Reason.piNotOnSLDB);
                    }

                    return resultFMnoPI; // use FMnoPI result
                }

                return resultFMPI;
            }

            
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ISupportBearingAngleDistances.cs
using System;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public interface ISupportBearingAngleDistances
    {
        /// <summary>
        /// Returns the two distance values of this polygon for the given bearing angle.
        /// </summary>
        /// <param name="bearingAngle"></param>
        /// <returns></returns>
        Distances GetDistancesForBearingAngle(double bearingAngle);
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ReceptionAreaPolygonAngleDivisor36.cs
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;

namespace SLDBService.Services.UnknownStation
{
    public class ReceptionAreaPolygonAngleDivisor36 : IReceptionAreaPolygon, ISupportBearingAngleDistances
    {
        public const int AngleDivisor = 36;
        private Dictionary<int, int> _polygonDistancesHm { get; }

        private int? _cachedMinimum;

        public ReceptionAreaPolygonAngleDivisor36(string polygonDistancesHm)
        {
            _polygonDistancesHm =
                polygonDistancesHm
                    .Split(',')
                    .Select((x, idx) => new { DistanceAtAngle = Int32.Parse(x), Angle = idx * 10 })
                    .ToDictionary(x => x.Angle, x => x.DistanceAtAngle);
        }

        /// <summary>
        /// If minimum of all distances of this polygon is greater than the given distanceValueHm, returns true, otherwise false.
        /// </summary>
        /// <param name="distanceValueHm"></param>
        /// <returns></returns>
        public override bool Contains(int distanceValueHm)
        {
            if (_cachedMinimum == null)
            {
                _cachedMinimum = _polygonDistancesHm.Values.Min();
            }

            return distanceValueHm <= _cachedMinimum.Value;
        }

        /// <summary>
        /// Returns the two distance values of this polygon for the given bearing angle.
        /// </summary>
        /// <param name="bearingAngle"></param>
        /// <returns></returns>
        public Distances GetDistancesForBearingAngle(double bearingAngle)
        {
            int index1 = ((int)Math.Floor(bearingAngle / 10)) * 10;
            int index2 = (((int)Math.Floor((bearingAngle + 10) / 10)) * 10) % 360;

            return new Distances
            {
                Distance1 = new DistanceAtAngle
                {
                    Angle = index1,
                    DistanceHm = _polygonDistancesHm[index1]
                },
                Distance2 = new DistanceAtAngle
                {
                    Angle = index2,
                    DistanceHm = _polygonDistancesHm[index2]
                }
            };
        }
    }
}
```

```csharp
// FILEPATH: ./Services/UnknownStation/ResolveUnknownStationHD_FM.cs
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Datadog.Trace;
using Microsoft.ApplicationInsights;
using SLDBService.Data;
using SLDBService.Database;
using SLDBService.Models;

namespace SLDBService.Services.UnknownStation
{
    public class ResolveUnknownStationHD_FM : ResolveUnknownStation
    {
        private static class SqlQuery
        {
            // Parameters: @Frequency, @BroadcastingStandardId, @StationCallSign, @SubchannelId
            // Returns: { linkingId, muxId, receptionAreaId, frequencyId, transmitterId }
            public const string Step1 =
                @"SELECT 
	                muxMap.linkingId,
	                recMap.muxId,
	                recMap.receptionAreaId,
	                recMap.frequencyId,
	                rec.transmitterId
                  FROM receptionAreaToBroadcasterMappingTable recMap
                  INNER JOIN muxToServiceMappingTable muxMap ON muxMap.muxId = recMap.muxId
                  INNER JOIN receptionAreaTable rec ON rec.receptionAreaId = recMap.receptionAreaId
                  WHERE recMap.frequencyId = (SELECT frequencyId FROM frequencyTable WHERE frequencyInKhz = @Frequency AND broadcastStandardNameId = @broadcastingStandardId)
                  AND recMap.stationCallSign = @StationCallSign
                  AND muxMap.subchannelId = @SubchannelId";
        }

        public ResolveUnknownStationHD_FM(IConnectionFactory connectionFactory, IServiceTimeSharing serviceTimeSharing, TelemetryClient logger)
            : base(connectionFactory, serviceTimeSharing, logger)
        {
        }

        public override int BroadcastingStandardNameId => 9;

        protected override async Task<UnknownStationLookupResult> Resolve(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            using (var scope = Tracer.Instance.StartActive("ResolveUnknownStationHD_FM.Resolve"))
            {
                var result = await QueryStep1(connection, request,cancellationToken).ConfigureAwait(false);
                result = result.DistinctBy(x => x.linkingId);
                // STEP 1 result count:
                // != 1->NotFound
                // == 1->EXIT
                var count = result.Count();

                if (count == 1)
                {
                    var hit = result.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                var reducedCandidates = await ReduceByTimeSharing(connection, result, request.GetTimestamp(),cancellationToken).ConfigureAwait(false);
                if (reducedCandidates.Count() == 1)
                {
                    var hit = reducedCandidates.Single();

                    return UnknownStationLookupResult.Found(hit.linkingId, hit.muxId, hit.receptionAreaId, hit.frequencyId, hit.transmitterId);
                }

                return UnknownStationLookupResult.NotFound("HDFMnotfound");
            }

        }

        private Task<IEnumerable<ResultModel>> QueryStep1(IDbConnection connection, UnknownStationRequest request,CancellationToken cancellationToken)
        {
            return connection.QueryCachedUnknownStationsAsync<ResultModel>(
                    SqlQuery.Step1,
                    new
                    {
                        Frequency = request.Frequency(),
                        BroadcastingStandardId = request.BroadcastStandard,
                        SubchannelId = request.SubchannelID,
                        StationCallSign = request.StationCallSign()
                    },cancellationToken);
        }
    }
}
```