using DeepCore.Log;
using System;
using System.Collections.Specialized;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ThreeLives.Service.Admin;

namespace ThreeLives.Service.Admin
{


    public class HttpServer : IDisposable
    {
        private const string NotFoundResponse = "<!doctype html><html><body>Resource not found</body></html>";
        private readonly HttpListener httpListener;
        private readonly CancellationTokenSource cts = new CancellationTokenSource();
        private readonly string prefixPath;
        private AdminServer srv;
        protected readonly Logger log;

        private Task<Task> processingTask;

        public HttpServer(string listenerUriPrefix, AdminServer srv, Logger log)
        {
            this.prefixPath = ParsePrefixPath(listenerUriPrefix);
            this.httpListener = new HttpListener();
            this.httpListener.Prefixes.Add(listenerUriPrefix);
            this.srv = srv;
            this.log = log;
        }

        private static string ParsePrefixPath(string listenerUriPrefix)
        {
            var match = Regex.Match(listenerUriPrefix, @"https?://(?:[^/]*)(?:\:\d+)?/(.*)");
            if (match.Success)
            {
                return match.Groups[1].Value.ToLowerInvariant();
            }
            else
            {
                return string.Empty;
            }
        }

        public void Start()
        {
            this.httpListener.Start();
            HttpServer httpServer = this;
            httpServer.processingTask = Task.Factory.StartNew(ProcessRequests, TaskCreationOptions.LongRunning);
        }

        public static NameValueCollection ParseQueryString(string query)
        {
            if (query.StartsWith("?"))
            {
                query = query.Substring(1);
            }
            var ret = new NameValueCollection();
            foreach (string pair in query.Split('&'))
            {
                string[] kv = pair.Split('=');

                string key = kv.Length == 1
                  ? null : Uri.UnescapeDataString(kv[0]).Replace('+', ' ');

                string[] values = Uri.UnescapeDataString(
                  kv.Length == 1 ? kv[0] : kv[1]).Replace('+', ' ').Split(',');

                foreach (string value in values)
                {
                    ret.Add(key, value);
                }
            }
            return ret;
        }

        private async Task ProcessRequests()
        {
            while (!this.cts.IsCancellationRequested)
            {
                try
                {
                    var context = await this.httpListener.GetContextAsync();
                    try
                    {
                        await ProcessRequest(context).ConfigureAwait(false);
                        context.Response.Close();
                    }
                    catch (Exception ex)
                    {
                        context.Response.StatusCode = 500;
                        context.Response.StatusDescription = "Internal Server Error";
                        context.Response.Close();
                        log.ErrorFormat("Error processing HTTP request\n{0}", ex);
                    }
                }
                catch (ObjectDisposedException ex)
                {
                    if ((ex.ObjectName == this.httpListener.GetType().FullName) && (this.httpListener.IsListening == false))
                    {
                        return; // listener is closed/disposed
                    }
                    log.ErrorFormat("Error processing HTTP request\n{0}", ex);
                }
                catch (HttpListenerException ex)
                {
                    HttpListenerException httpException = ex as HttpListenerException;
                    if (httpException == null || httpException.ErrorCode != 995)// IO operation aborted
                    {
                        log.ErrorFormat("Error processing HTTP request\n{0}", ex);
                    }
                }
                catch (Exception ex)
                {
                    log.ErrorFormat("Error processing HTTP request\n{0}", ex);
                }
            }
        }

        private async Task ProcessRequest(HttpListenerContext context)
        {
            if (context.Request.HttpMethod.ToUpperInvariant() != "POST")
            {
                await WriteNotFound(context);
                return;
            }

            //var urlPath = context.Request.Url.AbsolutePath.Substring(this.prefixPath.Length)
            //    .ToLowerInvariant();
            var url = context.Request.Url;

            var urlPath = url.PathAndQuery;

            if (urlPath.StartsWith("/api/"))
            {
                //限制请求体大小100k以内
                if (context.Request.ContentLength64 < 100 * 1000)
                {
                    var q = url.Query;
                    var param = ParseQueryString(q);

                    //byte[] byts = new byte[context.Request.InputStream.Length];

                    //await context.Request.InputStream.ReadAsync(byts, 0, byts.Length);
                    //string req = System.Text.Encoding.UTF8.GetString(byts);
                    //Console.WriteLine(urlPath);
                    StringRequest sq = new StringRequest();
                    sq.token = param.Get("token");
                    sq.content = param.Get("content");
                    sq.stamp = param.Get("stamp");

                    TaskCompletionSource<string> tcs = new TaskCompletionSource<string>();
                    await srv.Execute(async () =>
                    {
                        try
                        {
                            string rsp = await srv.OnHandleHttpRequest(sq);
                            tcs.SetResult(rsp);
                        }
                        catch (Exception e)
                        {
                            tcs.SetException(e);
                        }
                    });
                    if (tcs.Task.IsFaulted)
                    {
                        throw tcs.Task.Exception;
                    }
                    await WriteString(context, tcs.Task.Result, "application/json");
                    return;
                }

            }

            await WriteNotFound(context);

        }

        private static Task WritePong(HttpListenerContext context)
        {
            return WriteString(context, "pong", "text/plain");
        }

        private static async Task WriteFavIcon(HttpListenerContext context)
        {
            context.Response.ContentType = "image/png";
            context.Response.StatusCode = 200;
            context.Response.StatusDescription = "OK";
            using (var stream = File.Open("icon.png", FileMode.Open))
            {
                var output = context.Response.OutputStream;
                await stream.CopyToAsync(output);
            }
        }

        private static Task WriteNotFound(HttpListenerContext context)
        {
            return WriteString(context, "", "application/json", 404, "NOT FOUND");
        }

        private static async Task WriteString(HttpListenerContext context, string data, string contentType,
            int httpStatus = 200, string httpStatusDescription = "OK")
        {
            AddCORSHeaders(context.Response);
            AddNoCacheHeaders(context.Response);

            context.Response.ContentType = contentType;
            context.Response.StatusCode = httpStatus;
            context.Response.StatusDescription = httpStatusDescription;
            context.Response.ContentEncoding = Encoding.UTF8;

            var acceptsGzip = AcceptsGzip(context.Request);
            if (!acceptsGzip)
            {
                byte[] buffer = Encoding.UTF8.GetBytes(data);
                context.Response.ContentLength64 = buffer.Length;
                await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                context.Response.OutputStream.Close();
                context.Response.Close();
            }
            else
            {
                context.Response.AddHeader("Content-Encoding", "gzip");
                using (GZipStream gzip = new GZipStream(context.Response.OutputStream, CompressionMode.Compress, true))
                using (var writer = new StreamWriter(gzip, Encoding.UTF8, 4096, true))
                {
                    await writer.WriteAsync(data);
                }
            }
        }


        private static bool AcceptsGzip(HttpListenerRequest request)
        {
            string encoding = request.Headers["Accept-Encoding"];
            if (string.IsNullOrEmpty(encoding))
            {
                return false;
            }

            return encoding.Contains("gzip");
        }

        private static void AddNoCacheHeaders(HttpListenerResponse response)
        {
            response.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate");
            response.Headers.Add("Pragma", "no-cache");
            response.Headers.Add("Expires", "0");
        }

        private static void AddCORSHeaders(HttpListenerResponse response)
        {
            response.Headers.Add("Access-Control-Allow-Origin", "*");
            response.Headers.Add("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
        }

        private void Stop()
        {
            cts.Cancel();
            if (processingTask != null && !processingTask.IsCompleted)
            {
                processingTask.Wait();
            }
            if (this.httpListener.IsListening)
            {
                this.httpListener.Stop();
                this.httpListener.Prefixes.Clear();
            }
        }

        public void Dispose()
        {
            this.Stop();
            this.httpListener.Close();
            using (this.cts) { }
            using (this.httpListener) { }
        }
    }
}