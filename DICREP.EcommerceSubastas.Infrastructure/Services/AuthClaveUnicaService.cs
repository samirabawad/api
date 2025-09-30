// DICREP.EcommerceSubastas.Infrastructure/Services/AuthClaveUnicaService.cs
using DICREP.EcommerceSubastas.Application.DTOs.Auth;
using DICREP.EcommerceSubastas.Application.Interfaces;
using DICREP.EcommerceSubastas.Domain.Entities;
using DICREP.EcommerceSubastas.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DICREP.EcommerceSubastas.Infrastructure.Services
{
    public class AuthClaveUnicaService : IAuthClaveUnicaService
    {
        private readonly EcoCircularContext _context;
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public AuthClaveUnicaService(
            EcoCircularContext context,
            IConfiguration configuration,
            HttpClient httpClient)
        {
            _context = context;
            _configuration = configuration;
            _httpClient = httpClient;
            _logger = Log.ForContext<AuthClaveUnicaService>();
        }

        public async Task<ClaveUnicaTokenResponse?> ExchangeCodeForTokenAsync(string code, string state)
        {
            try
            {
                var clientId = _configuration["ClaveUnica:ClientId"];
                var clientSecret = _configuration["ClaveUnica:ClientSecret"];
                var redirectUri = _configuration["ClaveUnica:RedirectUri"];
                var tokenEndpoint = "https://accounts.claveunica.gob.cl/openid/token";



                var requestData = new Dictionary<string, string>
                {
                    {"grant_type", "authorization_code"},
                    {"client_id", clientId},
                    {"client_secret", clientSecret},
                    {"code", code},
                    {"redirect_uri", redirectUri}
                };

                var requestContent = new FormUrlEncodedContent(requestData);
                _logger.Information("Intercambiando código por token con Clave Única");
                var response = await _httpClient.PostAsync(tokenEndpoint, requestContent);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.Error("Error al intercambiar código: {StatusCode} - {Content}",
                        response.StatusCode, errorContent);
                    return null;
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ClaveUnicaTokenResponse>(jsonResponse, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error inesperado al intercambiar código por token");
                return null;
            }
        }

        public async Task<ClaveUnicaUserInfo?> GetUserInfoFromClaveUnicaAsync(string accessToken)
        {
            try
            {
                var userInfoEndpoint = "https://accounts.claveunica.gob.cl/openid/userinfo";
                using var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
                request.Headers.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                _logger.Information("Obteniendo información del usuario desde Clave Única");
                var response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.Error("Error al obtener info del usuario: {StatusCode} - {Content}",
                        response.StatusCode, errorContent);
                    return null;
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ClaveUnicaUserInfo>(jsonResponse, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                });
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error inesperado al obtener información del usuario");
                return null;
            }
        }

        public async Task<Empleado?> FindOrCreateUserFromClaveUnicaAsync(ClaveUnicaUserInfo userInfo)
        {
            try
            {
                var rutSinFormato = userInfo.Sub;
                var rutNumerico = ExtraerRutNumerico(rutSinFormato);
                var digitoVerificador = ExtraerDigitoVerificador(rutSinFormato);

                _logger.Information("Buscando usuario con RUT numérico: {RutNumerico}-{Dv}",
                    rutNumerico, digitoVerificador);

                var usuario = await _context.Empleados
                    .Include(e => e.Perfil)
                    .Include(e => e.Sucursal)
                    .FirstOrDefaultAsync(e => e.EmpRut == rutNumerico);

                if (usuario != null)
                {
                    _logger.Information("Usuario encontrado: {EmpId} - {EmpUsuario}",
                        usuario.EmpId, usuario.EmpUsuario);
                    await ActualizarInformacionUsuarioAsync(usuario, userInfo);
                    return usuario;
                }

                var permitirCreacion = _configuration.GetValue<bool>("ClaveUnica:AllowAutoUserCreation", false);
                if (!permitirCreacion)
                {
                    _logger.Warning("Usuario con RUT {RutNumerico} no encontrado y creación automática deshabilitada",
                        rutNumerico);
                    return null;
                }

                return await CrearNuevoUsuarioAsync(userInfo, rutNumerico, digitoVerificador);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error al buscar o crear usuario desde Clave Única");
                return null;
            }
        }

        public JwtTokenResult GenerateTokens(Empleado usuario)
        {
            var jwtSecret = _configuration["Jwt:Secret"];
            var jwtIssuer = _configuration["Jwt:Issuer"];
            var jwtAudience = _configuration["Jwt:Audience"];
            var accessTokenExpireMinutes = _configuration.GetValue<int>("Jwt:AccessTokenExpireMinutes", 15);
            var refreshTokenExpireDays = _configuration.GetValue<int>("Jwt:RefreshTokenExpireDays", 7);



            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Claims para Access Token
            var accessTokenClaims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, usuario.EmpId.ToString()),
                new(ClaimTypes.Name, usuario.EmpUsuario),
                new(ClaimTypes.Email, usuario.EmpCorreo ?? ""),
                new("empId", usuario.EmpId.ToString()),
                new("empNombre", usuario.EmpNombre),
                new("empApellido", usuario.EmpApellido),
                new("perfilId", usuario.PerfilId.ToString()),
                new("perfilNombre", usuario.Perfil?.PerfilNombre ?? ""),
                new("sucursalId", usuario.SucursalId.ToString()),
                new("sucursalNombre", usuario.Sucursal?.SucursalNombre ?? ""),
                new("token_type", "access")
            };

            var accessToken = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: accessTokenClaims,
                expires: DateTime.UtcNow.AddMinutes(accessTokenExpireMinutes),
                signingCredentials: creds
            );

            // Claims para Refresh Token (mínimos)
            var refreshTokenClaims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, usuario.EmpId.ToString()),
                new("empId", usuario.EmpId.ToString()),
                new("token_type", "refresh"),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var refreshToken = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: refreshTokenClaims,
                expires: DateTime.UtcNow.AddDays(refreshTokenExpireDays),
                signingCredentials: creds
            );

            return new JwtTokenResult
            {
                Token = new JwtSecurityTokenHandler().WriteToken(accessToken),
                RefreshToken = new JwtSecurityTokenHandler().WriteToken(refreshToken),
                Expiration = DateTime.UtcNow.AddMinutes(accessTokenExpireMinutes),
                RefreshExpiration = DateTime.UtcNow.AddDays(refreshTokenExpireDays)
            };
        }

        public async Task<JwtTokenResult?> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var jwtSecret = _configuration["Jwt:Secret"];
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(jwtSecret);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _configuration["Jwt:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = _configuration["Jwt:Audience"],
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                var principal = tokenHandler.ValidateToken(refreshToken, validationParameters, out var validatedToken);

                var tokenTypeClaim = principal.FindFirst("token_type")?.Value;
                if (tokenTypeClaim != "refresh")
                {
                    _logger.Warning("Token no es de tipo refresh");
                    return null;
                }

                var empIdClaim = principal.FindFirst("empId")?.Value;
                if (string.IsNullOrEmpty(empIdClaim) || !int.TryParse(empIdClaim, out var empId))
                {
                    _logger.Warning("Token no contiene empId válido");
                    return null;
                }

                var usuario = await _context.Empleados
                    .Include(e => e.Perfil)
                    .Include(e => e.Sucursal)
                    .FirstOrDefaultAsync(e => e.EmpId == empId && e.EmpActivo);

                if (usuario == null)
                {
                    _logger.Warning("Usuario {EmpId} no encontrado o inactivo", empId);
                    return null;
                }

                return GenerateTokens(usuario);
            }
            catch (SecurityTokenExpiredException)
            {
                _logger.Warning("Refresh token expirado");
                return null;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error al validar refresh token");
                return null;
            }
        }

        public async Task UpdateLastLoginAsync(int empId)
        {
            try
            {
                var usuario = await _context.Empleados.FindAsync(empId);
                if (usuario != null)
                {
                    usuario.EmpFechaLog = DateTime.Now;
                    await _context.SaveChangesAsync();
                    _logger.Information("Último login actualizado para usuario {EmpId}", empId);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error al actualizar último login para usuario {EmpId}", empId);
            }
        }

        // Métodos privados auxiliares
        private async Task<Empleado> CrearNuevoUsuarioAsync(ClaveUnicaUserInfo userInfo, int rutNumerico, string digitoVerificador)
        {
            _logger.Information("Creando nuevo usuario desde Clave Única con RUT {RutNumerico}-{Dv}",
                rutNumerico, digitoVerificador);

            var perfilDefecto = await _context.Perfiles
                .FirstOrDefaultAsync(p => p.PerfilNombre.Contains("Usuario") || p.PerfilId == 1);

            var sucursalDefecto = await _context.Sucursales
                .FirstOrDefaultAsync(s => s.SucursalNombre.Contains("Central") || s.SucursalId == 1);

            var primerNombre = userInfo.NameInfo?.Given?.FirstOrDefault() ?? "Sin nombre";
            var primerApellido = userInfo.NameInfo?.Family?.FirstOrDefault() ?? "Sin apellido";

            var nuevoUsuario = new Empleado
            {
                EmpRut = rutNumerico,
                EmpRutDig = digitoVerificador,
                EmpNombre = NormalizarNombre(primerNombre),
                EmpApellido = NormalizarNombre(primerApellido),
                EmpCorreo = userInfo.Email?.ToLower() ?? "",
                EmpUsuario = GenerarNombreUsuario(userInfo),
                EmpActivo = true,
                AuthMethod = 2,
                PerfilId = perfilDefecto?.PerfilId ?? 1,
                SucursalId = sucursalDefecto?.SucursalId ?? 1,
                ClaveUnicaSub = userInfo.Sub
            };

            _context.Empleados.Add(nuevoUsuario);
            await _context.SaveChangesAsync();

            _logger.Information("Usuario creado exitosamente: {EmpId} - {EmpUsuario}",
                nuevoUsuario.EmpId, nuevoUsuario.EmpUsuario);

            return await _context.Empleados
                .Include(e => e.Perfil)
                .Include(e => e.Sucursal)
                .FirstAsync(e => e.EmpId == nuevoUsuario.EmpId);
        }

        private async Task ActualizarInformacionUsuarioAsync(Empleado usuario, ClaveUnicaUserInfo userInfo)
        {
            var actualizado = false;

            if (string.IsNullOrEmpty(usuario.ClaveUnicaSub))
            {
                usuario.ClaveUnicaSub = userInfo.Sub;
                actualizado = true;
            }

            if (!string.IsNullOrEmpty(userInfo.Email) &&
                !string.Equals(usuario.EmpCorreo, userInfo.Email, StringComparison.OrdinalIgnoreCase))
            {
                usuario.EmpCorreo = userInfo.Email.ToLower();
                actualizado = true;
            }

            if (actualizado)
            {
                await _context.SaveChangesAsync();
                _logger.Information("Información del usuario {EmpId} actualizada", usuario.EmpId);
            }
        }

        private int ExtraerRutNumerico(string rutSinFormato)
        {
            if (string.IsNullOrEmpty(rutSinFormato) || rutSinFormato.Length < 2)
                return 0;

            var numero = rutSinFormato.Substring(0, rutSinFormato.Length - 1);
            return int.TryParse(numero, out var result) ? result : 0;
        }

        private string ExtraerDigitoVerificador(string rutSinFormato)
        {
            if (string.IsNullOrEmpty(rutSinFormato) || rutSinFormato.Length < 1)
                return "0";

            return rutSinFormato.Substring(rutSinFormato.Length - 1).ToUpper();
        }

        private string GenerarNombreUsuario(ClaveUnicaUserInfo userInfo)
        {
            var nombre = userInfo.NameInfo?.Given?.FirstOrDefault()?.ToLower() ?? "usuario";
            var apellido = userInfo.NameInfo?.Family?.FirstOrDefault()?.ToLower() ?? "";

            var usuario = string.IsNullOrEmpty(apellido)
                ? nombre
                : $"{nombre.FirstOrDefault()}{apellido}";

            usuario = Regex.Replace(usuario, @"[^a-zA-Z0-9]", "");
            return usuario.Length > 30 ? usuario.Substring(0, 30) : usuario;
        }

        private string NormalizarNombre(string nombre)
        {
            if (string.IsNullOrWhiteSpace(nombre))
                return "";

            return CultureInfo.CurrentCulture.TextInfo.ToTitleCase(nombre.ToLower().Trim());
        }
    }
}