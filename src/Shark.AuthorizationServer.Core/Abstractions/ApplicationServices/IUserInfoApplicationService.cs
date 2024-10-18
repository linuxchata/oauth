using System.Security.Claims;
using Shark.AuthorizationServer.Core.Responses.UserInfo;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IUserInfoApplicationService
{
    UserInfoBaseResponse Execute(ClaimsPrincipal claimsPrincipal);
}
