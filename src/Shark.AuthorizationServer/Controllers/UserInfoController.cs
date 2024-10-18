﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class UserInfoController(
    IUserInfoApplicationService userInfoApplicationService) : ControllerBase
{
    private readonly IUserInfoApplicationService _userInfoApplicationService = userInfoApplicationService;

    [Authorize]
    [HttpGet]
    public IActionResult Get()
    {
        return Ok();
    }

    [Authorize]
    [HttpPost]
    public IActionResult Post()
    {
        return Ok();
    }
}