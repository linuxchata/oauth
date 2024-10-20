using Microsoft.Extensions.Caching.Distributed;
using Shark.Sample.Client.Abstractions.Services;

namespace Shark.Sample.Client.Services;

public sealed class StateStore(IDistributedCache cache) : IStateStore
{
    private readonly IDistributedCache _cache = cache;

    public string? Get(string key)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(key, nameof(key));

        return _cache.GetString(key);
    }

    public void Add(string key, string state)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(key, nameof(key));
        ArgumentNullException.ThrowIfNullOrWhiteSpace(state, nameof(state));

        _cache.SetString(key, state);
    }
}
