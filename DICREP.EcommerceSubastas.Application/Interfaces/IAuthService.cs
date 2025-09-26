
// Services/IAuthService.cs
using DICREP.EcommerceSubastas.Domain.Entities;

public interface IAuthService
{
    Task<Empleado?> FindOrCreateUserFromClaveUnica(ClaveUnicaUserInfo userInfo);
    Task<TokenResult> GenerateTokens(Empleado usuario);
    Task<TokenResult?> RefreshToken(string refreshToken);
    Task UpdateLastLogin(int empId);
    Task InvalidateToken(string token);
}