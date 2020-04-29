using DeepCrystal.RPC;
using System;
using System.Threading.Tasks;

namespace DeepHttpService
{
    public class HttpService : IService
    {
        public HttpService(ServiceStartInfo start) : base(start) { }
        protected override void OnDisposed() { }
        protected override async Task OnStartAsync()
        {

        }
        protected override Task OnStopAsync(ServiceStopInfo reason)
        {
            return Task.CompletedTask;
        }
    }
}
