using DeepCrystal.RPC;
using System;
using System.Net;
using System.Threading.Tasks;

namespace DeepHttpService
{
    public class HttpService : IService
    {
        private const string NotFoundResponse = "<!doctype html><html><body>Resource not found</body></html>";
        private readonly string prefixPath;
        private readonly HttpListener httpListener;

        public HttpService(ServiceStartInfo start) : base(start)
        {
            this.prefixPath = start.Config["HTTPListen"].ToString();
            this.httpListener = new HttpListener();
            this.httpListener.Prefixes.Add(prefixPath);
        }
        protected override void OnDisposed() { }
        protected override async Task OnStartAsync()
        {
            this.httpListener.Start();
        }
        protected override Task OnStopAsync(ServiceStopInfo reason)
        {
            return Task.CompletedTask;
        }
    }
}
