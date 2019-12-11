using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(FDDWeb.Startup))]
namespace FDDWeb
{
    public partial class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureAuth(app);
        }
    }
}
