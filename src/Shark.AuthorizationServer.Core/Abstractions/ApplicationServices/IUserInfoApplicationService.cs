using System.Security.Claims;
using Shark.AuthorizationServer.Core.Responses.UserInfo;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IUserInfoApplicationService
{
    Task<UserInfoBaseResponse> Execute(ClaimsPrincipal claimsPrincipal);
}
