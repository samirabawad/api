// Controllers/AuthController.cs
using DICREP.EcommerceSubastas.Application.DTOs.Auth;
using DICREP.EcommerceSubastas.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DICREP.EcommerceSubastas.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthClaveUnicaService _authClaveUnicaService;

        public AuthController(IAuthClaveUnicaService authClaveUnicaService)
        {
            _authClaveUnicaService = authClaveUnicaService;
        }

        [HttpPost("clave-unica")]
        public async Task<IActionResult> LoginClaveUnica([FromBody] ClaveUnicaLoginRequest request)
        {
            try
            {
                var tokenResponse = await _authClaveUnicaService.ExchangeCodeForTokenAsync(request.Code, request.State);

                if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
                {
                    return BadRequest(new { success = false, message = "Error al obtener token de Clave Única" });
                }

                var userInfo = await _authClaveUnicaService.GetUserInfoFromClaveUnicaAsync(tokenResponse.AccessToken);

                if (userInfo == null)
                {
                    return BadRequest(new { success = false, message = "Error al obtener información del usuario" });
                }

                var usuario = await _authClaveUnicaService.FindOrCreateUserFromClaveUnicaAsync(userInfo);

                if (usuario == null || !usuario.EmpActivo)
                {
                    return Unauthorized(new { success = false, message = "Usuario no autorizado o inactivo" });
                }

                var jwtTokens = _authClaveUnicaService.GenerateTokens(usuario);

                await _authClaveUnicaService.UpdateLastLoginAsync(usuario.EmpId);

                return Ok(new LoginResponse
                {
                    Success = true,
                    Token = jwtTokens.Token,              // ✅ Correcto
                    RefreshToken = jwtTokens.RefreshToken,
                    User = new UserDto
                    {
                        EmpId = usuario.EmpId,
                        EmpUsuario = usuario.EmpUsuario,
                        EmpNombre = usuario.EmpNombre,
                        EmpApellido = usuario.EmpApellido,
                        EmpCorreo = usuario.EmpCorreo,
                        PerfilNombre = usuario.Perfil?.PerfilNombre,
                        SucursalNombre = usuario.Sucursal?.SucursalNombre
                    },
                    Message = "Login exitoso con Clave Única"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { success = false, message = "Error interno del servidor", error = ex.Message });
            }
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var result = await _authClaveUnicaService.RefreshTokenAsync(request.RefreshToken);

                if (result == null)
                {
                    return Unauthorized(new { success = false, message = "Refresh token inválido o expirado" });
                }

                return Ok(new
                {
                    success = true,
                    token = result.Token,              // ✅ Correcto
                    refreshToken = result.RefreshToken,
                    message = "Token refrescado exitosamente"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { success = false, message = "Error al refrescar token", error = ex.Message });
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public IActionResult Logout()
        {
            return Ok(new { success = false, message = "Logout exitoso. Elimine los tokens del cliente." });
        }

        [HttpGet("validate-token")]
        [Authorize]
        public IActionResult ValidateToken()
        {
            return Ok(new { valid = true, user = User.Identity?.Name });
        }
    }
}