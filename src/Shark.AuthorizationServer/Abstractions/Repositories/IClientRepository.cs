﻿namespace Shark.AuthorizationServer.Abstractions.Repositories;

public interface IClientRepository
{
    Models.Client? GetById(string? id);

    void Add(Models.Client client);
}