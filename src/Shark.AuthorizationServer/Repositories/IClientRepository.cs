namespace Shark.AuthorizationServer.Repositories;

public interface IClientRepository
{
    Models.Client? GetById(string? id);
}