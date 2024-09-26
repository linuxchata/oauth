using Microsoft.AspNetCore.Mvc;

namespace Shark.AuthorizationServer.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthorizeController() : ControllerBase
{
    [HttpGet]
    public IActionResult Get(
        [FromQuery] string response_type,
        [FromQuery] string client_id,
        [FromQuery] string redirect_url,
        [FromQuery] string state)
    {
        return RedirectToPage(
            "/Login",
            new
            {
                clientId = client_id,
                state = state,
                redirectBaseUrl = redirect_url,
            });
    }
}
