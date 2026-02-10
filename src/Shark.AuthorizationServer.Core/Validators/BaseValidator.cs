namespace Shark.AuthorizationServer.Core.Validators;

public abstract class BaseValidator<T>
    where T : class
{
    protected static T? CheckAll(params T?[] responses)
    {
        foreach (var response in responses)
        {
            if (response != null)
            {
                return response;
            }
        }

        return null;
    }
}