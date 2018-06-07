using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EVEStandard.ASPNETCoreSample.Controllers
{
    [Authorize]
    public class SecureController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}