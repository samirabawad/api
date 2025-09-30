// DICREP.EcommerceSubastas.Application/DTOs/Auth/JwtTokenResult.cs
using System;

namespace DICREP.EcommerceSubastas.Application.DTOs.Auth
{
    public class JwtTokenResult
    {
        public string Token { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime Expiration { get; set; }
        public DateTime RefreshExpiration { get; set; }
    }
}