�
yC:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Security\ApiKeyAuth.cs
	namespace 	
DICREP
 
. 
EcommerceSubastas "
." #
API# &
.& '
Security' /
{ 
public 

static 
class 
	Constants !
{ 
public 
const 
string 
ApiKeyHeaderName ,
=- .
$str/ :
;: ;
public 
const 
string 

ApiKeyName &
=' (
$str) 3
;3 4
} 
public		 

	interface		 
IApiKeyValidation		 &
{

 
bool 
IsValid 
( 
string 
apiKey "
)" #
;# $
} 
public 

class 
ApiKeyValidation !
:" #
IApiKeyValidation$ 5
{ 
private 
readonly 
IConfiguration '
_cfg( ,
;, -
public 
ApiKeyValidation 
(  
IConfiguration  .
cfg/ 2
)2 3
=>4 6
_cfg7 ;
=< =
cfg> A
;A B
public 
bool 
IsValid 
( 
string "
apiKey# )
)) *
=>+ -
! 
string 
. 
IsNullOrEmpty !
(! "
apiKey" (
)( )
&&* ,
apiKey 
== 
_cfg 
. 
GetValue #
<# $
string$ *
>* +
(+ ,
	Constants, 5
.5 6

ApiKeyName6 @
)@ A
;A B
} 
} �
�C:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\SwaggerFilters\DevelopmentDocumentFilter.cs
public

 
class

 %
DevelopmentDocumentFilter

 &
:

' (
IDocumentFilter

) 8
{ 
private 
readonly 
IWebHostEnvironment (
_env) -
;- .
public 
%
DevelopmentDocumentFilter $
($ %
IWebHostEnvironment% 8
env9 <
)< =
=>> @
_envA E
=F G
envH K
;K L
public 

void 
Apply 
( 
OpenApiDocument %
doc& )
,) *!
DocumentFilterContext+ @
ctxA D
)D E
{ 
if 

( 
_env 
. 
EnvironmentName  
!=! #
$str$ 1
)1 2
{ 	
var 
rutasSandbox 
= 
ctx "
." #
ApiDescriptions# 2
. 
Where 
( 
ad 
=> 
ad 
.  
ActionDescriptor  0
.0 1
EndpointMetadata1 A
. 
OfType 
< $
DevelopmentOnlyAttribute 4
>4 5
(5 6
)6 7
.7 8
Any8 ;
(; <
)< =
)= >
. 
Select 
( 
ad 
=> 
$str !
+" #
ad$ &
.& '
RelativePath' 3
.3 4
TrimEnd4 ;
(; <
$char< ?
)? @
)@ A
. 
ToList 
( 
) 
; 
foreach 
( 
var 
ruta 
in  
rutasSandbox! -
)- .
doc 
. 
Paths 
. 
Remove  
(  !
ruta! %
)% &
;& '
} 	
} 
} ��
mC:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Program.cs
var 
builder 
= 
WebApplication 
. 
CreateBuilder *
(* +
args+ /
)/ 0
;0 1
builder 
. 
WebHost 
. 
ConfigureKestrel  
(  !
serverOptions! .
=>/ 1
{ 
serverOptions   
.   
AddServerHeader   !
=  " #
false  $ )
;  ) *
}!! 
)!! 
;!! 
builder** 
.** 
Services** 
.** 
AddDbContext** 
<** &
EcoCircular07082025Context** 8
>**8 9
(**9 :
options**: A
=>**B D
{++ 
options,, 
.,, 
UseSqlServer,, 
(,, 
builder-- 
.-- 
Configuration-- 
.-- 
GetConnectionString-- 1
(--1 2
$str--2 =
)--= >
,--> ?
providerOptions.. 
=>.. 
providerOptions.. *
...* + 
EnableRetryOnFailure..+ ?
(..? @
)..@ A
)// 	
;//	 

}00 
)00 
;00 
builder33 
.33 
Services33 
.33 
AddControllers33 
(33  
)33  !
;33! "
builder88 
.88 
Services88 
.88 
	AddScoped88 
<88 
IEmpleadoRepository88 .
,88. /
EmpleadoRepository880 B
>88B C
(88C D
)88D E
;88E F
builder99 
.99 
Services99 
.99 
	AddScoped99 
<99 $
IFuncionalidadRepository99 3
,993 4#
FuncionalidadRepository995 L
>99L M
(99M N
)99N O
;99O P
builder:: 
.:: 
Services:: 
.:: 
	AddScoped:: 
<:: 
IPerfilRepository:: ,
,::, -
PerfilRepository::. >
>::> ?
(::? @
)::@ A
;::A B
builder;; 
.;; 
Services;; 
.;; 
	AddScoped;; 
<;; $
IFichaProductoRepository;; 3
,;;3 4#
FichaProductoRepository;;5 L
>;;L M
(;;M N
);;N O
;;;O P
builder>> 
.>> 
Services>> 
.>> 
AddTransient>> 
<>>  
IFuncionalidadMapper>> 2
,>>2 3
FuncionalidadMapper>>4 G
>>>G H
(>>H I
)>>I J
;>>J K
builderAA 
.AA 
ServicesAA 
.AA 
AddAutoMapperAA 
(AA 
	AppDomainAA (
.AA( )
CurrentDomainAA) 6
.AA6 7
GetAssembliesAA7 D
(AAD E
)AAE F
)AAF G
;AAG H
builderGG 
.GG 
ServicesGG 
.GG 
	AddScopedGG 
<GG (
GetAllFuncionalidadesUseCaseGG 7
>GG7 8
(GG8 9
)GG9 :
;GG: ;
builderHH 
.HH 
ServicesHH 
.HH 
	AddScopedHH 
<HH !
GetAllPermisosUseCaseHH 0
>HH0 1
(HH1 2
)HH2 3
;HH3 4
builderII 
.II 
ServicesII 
.II 
	AddScopedII 
<II 
ReceiveFichaUseCaseII .
>II. /
(II/ 0
)II0 1
;II1 2
builderMM 
.MM 
ServicesMM 
.MM 
	AddScopedMM 
<MM 
IPermisoServiceMM *
,MM* +
PermisoServiceMM, :
>MM: ;
(MM; <
)MM< =
;MM= >
builderNN 
.NN 
ServicesNN 
.NN 
	AddScopedNN 
<NN !
IAuthorizationHandlerNN 0
,NN0 1
PermisoHandlerNN2 @
>NN@ A
(NNA B
)NNB C
;NNC D
builderSS 
.SS 
ServicesSS 
.SS 
	AddScopedSS 
<SS 
NormalizacionHelperSS .
,SS. /
NormalizacionHelperSS1 D
>SSD E
(SSE F
)SSF G
;SSG H
builderVV 
.VV 
ServicesVV 
.VV 
AddTransientVV 
<VV 
IApiKeyValidationVV /
,VV/ 0
ApiKeyValidationVV1 A
>VVA B
(VVB C
)VVC D
;VVD E
builderZZ 
.ZZ 
ServicesZZ 
.ZZ 
AddSingletonZZ 
<ZZ (
IAuthorizationPolicyProviderZZ :
,ZZ: ;!
PermisoPolicyProviderZZ< Q
>ZZQ R
(ZZR S
)ZZS T
;ZZT U
builder^^ 
.^^ 
Services^^ 
.^^ 
	AddScoped^^ 
<^^ 
IPasswordHasher^^ *
,^^* + 
BCryptPasswordHasher^^, @
>^^@ A
(^^A B
)^^B C
;^^C D
builderbb 
.bb 
Servicesbb 
.bb 
	Configurebb 
<bb 
JwtSettingsbb &
>bb& '
(bb' (
builderbb( /
.bb/ 0
Configurationbb0 =
.bb= >

GetSectionbb> H
(bbH I
$strbbI V
)bbV W
)bbW X
;bbX Y
buildercc 
.cc 
Servicescc 
.cc 
AddSingletoncc 
(cc 
spcc  
=>cc! #
spdd 
.dd 
GetRequiredServicedd 
<dd 
IOptionsdd "
<dd" #
JwtSettingsdd# .
>dd. /
>dd/ 0
(dd0 1
)dd1 2
.dd2 3
Valuedd3 8
)dd8 9
;dd9 :
builderee 
.ee 
Servicesee 
.ee 
	AddScopedee 
<ee 
IJwtTokenGeneratoree -
,ee- .
JwtTokenGeneratoree/ @
>ee@ A
(eeA B
)eeB C
;eeC D
builderii 
.ii 
Servicesii 
.ii 
AddSwaggerGenii 
(ii 
cii  
=>ii! #
{jj 
ckk 
.kk 
DocumentFilterkk 
<kk %
DevelopmentDocumentFilterkk .
>kk. /
(kk/ 0
)kk0 1
;kk1 2
}ll 
)ll 
;ll 
builderpp 
.pp 
Servicespp 
.pp 
AddAuthenticationpp "
(pp" #
optionspp# *
=>pp+ -
{qq 
optionsrr 
.rr %
DefaultAuthenticateSchemerr %
=rr& '
JwtBearerDefaultsrr( 9
.rr9 : 
AuthenticationSchemerr: N
;rrN O
optionsss 
.ss "
DefaultChallengeSchemess "
=ss# $
JwtBearerDefaultsss% 6
.ss6 7 
AuthenticationSchemess7 K
;ssK L
}tt 
)tt 
.xx 
AddJwtBearerxx 
(xx 
optionsxx 
=>xx 
{yy 
optionszz 
.zz %
TokenValidationParameterszz %
=zz& '
newzz( +%
TokenValidationParameterszz, E
{{{ 
ValidateIssuer|| 
=|| 
true|| 
,|| 
ValidateAudience}} 
=}} 
true}} 
,}}  
ValidateLifetime~~ 
=~~ 
true~~ 
,~~  $
ValidateIssuerSigningKey  
=! "
true# '
,' (
ValidIssuer
�� 
=
�� 
builder
�� 
.
�� 
Configuration
�� +
[
��+ ,
$str
��, @
]
��@ A
,
��A B
ValidAudience
�� 
=
�� 
builder
�� 
.
��  
Configuration
��  -
[
��- .
$str
��. D
]
��D E
,
��E F
IssuerSigningKey
�� 
=
�� 
new
�� "
SymmetricSecurityKey
�� 3
(
��3 4
Encoding
�� 
.
�� 
UTF8
�� 
.
�� 
GetBytes
�� "
(
��" #
builder
��# *
.
��* +
Configuration
��+ 8
[
��8 9
$str
��9 M
]
��M N
)
��N O
)
��O P
}
�� 
;
�� 
}�� 
)
�� 
;
�� 
builder�� 
.
�� 
Services
�� 
.
�� 
AddSwaggerGen
�� 
(
�� 
c
��  
=>
��! #
{�� 
c
�� 
.
�� 

SwaggerDoc
�� 
(
�� 
$str
�� 
,
�� 
new
�� 
OpenApiInfo
�� &
{
��' (
Title
��) .
=
��/ 0
$str
��1 9
,
��9 :
Version
��; B
=
��C D
$str
��E I
}
��J K
)
��K L
;
��L M
c
�� 
.
�� #
AddSecurityDefinition
�� 
(
�� 
$str
�� $
,
��$ %
new
��& )#
OpenApiSecurityScheme
��* ?
{
�� 
Description
�� 
=
�� 
$str
�� ,
,
��, -
Name
�� 
=
�� 
$str
�� 
,
�� 
In
�� 

=
�� 
ParameterLocation
�� 
.
�� 
Header
�� %
,
��% &
Type
�� 
=
��  
SecuritySchemeType
�� !
.
��! "
Http
��" &
,
��& '
Scheme
�� 
=
�� 
$str
�� 
}
�� 
)
�� 
;
�� 
c
�� 
.
�� $
AddSecurityRequirement
�� 
(
�� 
new
��  (
OpenApiSecurityRequirement
��! ;
{
�� 
{
�� 	
new
�� #
OpenApiSecurityScheme
�� %
{
�� 
	Reference
�� 
=
�� 
new
�� 
OpenApiReference
��  0
{
�� 
Id
�� 
=
�� 
$str
�� !
,
��! "
Type
�� 
=
�� 
ReferenceType
�� (
.
��( )
SecurityScheme
��) 7
}
�� 
}
�� 
,
�� 
new
�� 
string
�� 
[
�� 
]
�� 
{
�� 
}
�� 
}
�� 	
}
�� 
)
�� 
;
�� 
}�� 
)
�� 
;
�� 
builder�� 
.
�� 
Services
�� 
.
�� %
AddEndpointsApiExplorer
�� (
(
��( )
)
��) *
;
��* +
if�� 
(
�� 
builder
�� 
.
�� 
Environment
�� 
.
�� 
IsDevelopment
�� %
(
��% &
)
��& '
)
��' (
{�� 
builder
�� 
.
�� 
Configuration
�� 
.
�� 
AddUserSecrets
�� (
<
��( )
Program
��) 0
>
��0 1
(
��1 2
)
��2 3
;
��3 4
}�� 
Console�� 
.
�� 
	WriteLine
�� 
(
�� 
$"
�� 
$str
�� $
{
��$ %
builder
��% ,
.
��, -
Environment
��- 8
.
��8 9
EnvironmentName
��9 H
}
��H I
"
��I J
)
��J K
;
��K L
Env�� 
.
�� 
Load
�� 
(
�� 	
)
��	 

;
��
 
var�� 
apikeycl
�� 
=
�� 
Environment
�� 
.
�� $
GetEnvironmentVariable
�� 1
(
��1 2
$str
��2 <
)
��< =
;
��= >
var�� 
dbUrl
�� 	
=
��
 
Environment
�� 
.
�� $
GetEnvironmentVariable
�� .
(
��. /
$str
��/ M
)
��M N
;
��N O
var�� 
	JwtSecret
�� 
=
�� 
Environment
�� 
.
�� $
GetEnvironmentVariable
�� 2
(
��2 3
$str
��3 H
)
��H I
;
��I J
var�� 
	JwtIssuer
�� 
=
�� 
Environment
�� 
.
�� $
GetEnvironmentVariable
�� 2
(
��2 3
$str
��3 H
)
��H I
;
��I J
var�� 
JwtAudience
�� 
=
�� 
Environment
�� 
.
�� $
GetEnvironmentVariable
�� 4
(
��4 5
$str
��5 L
)
��L M
;
��M N
builder�� 
.
�� 
Configuration
�� 
.
�� %
AddEnvironmentVariables
�� -
(
��- .
)
��. /
;
��/ 0
var�� 
config
�� 

=
�� 
builder
�� 
.
�� 
Configuration
�� "
;
��" #
var�� 
connectionString
�� 
=
�� 
config
�� 
.
�� !
GetConnectionString
�� 1
(
��1 2
$str
��2 =
)
��= >
;
��> ?
var�� 
app
�� 
=
�� 	
builder
��
 
.
�� 
Build
�� 
(
�� 
)
�� 
;
�� 
app�� 
.
�� !
UseForwardedHeaders
�� 
(
�� 
new
�� %
ForwardedHeadersOptions
�� 3
{�� 
ForwardedHeaders
�� 
=
�� 
ForwardedHeaders
�� '
.
��' (
XForwardedFor
��( 5
|
��6 7
ForwardedHeaders
��8 H
.
��H I
XForwardedProto
��I X
}�� 
)
�� 
;
�� 
app�� 
.
�� 
UseStaticFiles
�� 
(
�� 
new
�� 
StaticFileOptions
�� (
{�� 
OnPrepareResponse
�� 
=
�� 
ctx
�� 
=>
�� 
{
�� 
ctx
�� 
.
�� 
Context
�� 
.
�� 
Response
�� 
.
�� 
Headers
�� $
.
��$ %
Remove
��% +
(
��+ ,
$str
��, 2
)
��2 3
;
��3 4
}
�� 
}�� 
)
�� 
;
�� 
app�� 
.
�� 
UseCors
�� 
(
�� 
policy
�� 
=>
�� 
{�� 
policy
�� 

.
��
 
AllowAnyOrigin
�� 
(
�� 
)
�� 
;
�� 
policy
�� 

.
��
 
AllowAnyMethod
�� 
(
�� 
)
�� 
;
�� 
policy
�� 

.
��
 
AllowAnyHeader
�� 
(
�� 
)
�� 
;
�� 
}�� 
)
�� 
;
�� 
using�� 
(
�� 
var
�� 

scope
�� 
=
�� 
app
�� 
.
�� 
Services
�� 
.
��  
CreateScope
��  +
(
��+ ,
)
��, -
)
��- .
{�� 
var
�� 
	dbContext
�� 
=
�� 
scope
�� 
.
�� 
ServiceProvider
�� )
.
��) * 
GetRequiredService
��* <
<
��< =(
EcoCircular07082025Context
��= W
>
��W X
(
��X Y
)
��Y Z
;
��Z [
try
�� 
{
�� 
if
�� 

(
�� 
!
�� 
	dbContext
�� 
.
�� 
Database
�� 
.
��  

CanConnect
��  *
(
��* +
)
��+ ,
)
��, -
{
�� 	
Console
�� 
.
�� 
	WriteLine
�� 
(
�� 
$str
�� J
)
��J K
;
��K L
}
�� 	
else
�� 
{
�� 	
Console
�� 
.
�� 
	WriteLine
�� 
(
�� 
$str
�� C
)
��C D
;
��D E
}
�� 	
}
�� 
catch
�� 	
(
��
 
	Exception
�� 
ex
�� 
)
�� 
{
�� 
Console
�� 
.
�� 
	WriteLine
�� 
(
�� 
$str
�� P
)
��P Q
;
��Q R
Console
�� 
.
�� 
	WriteLine
�� 
(
�� 
ex
�� 
.
�� 
ToString
�� %
(
��% &
)
��& '
)
��' (
;
��( )
}
�� 
}�� 
if�� 
(
�� 
app
�� 
.
�� 
Environment
�� 
.
�� 
IsDevelopment
�� !
(
��! "
)
��" #
||
��$ &
app
�� 
.
�� 
Environment
�� 
.
�� 
IsProduction
��  
(
��  !
)
��! "
||
��# %
app
�� 
.
�� 
Environment
�� 
.
�� 
	IsStaging
�� 
(
�� 
)
�� 
||
��  "
app
�� 
.
�� 
Environment
�� 
.
�� 
EnvironmentName
�� #
==
��$ &
$str
��' 0
)
�� 
{�� 
Console
�� 
.
�� 
	WriteLine
�� 
(
�� 
$"
�� 
$str
�� (
{
��( )
app
��) ,
.
��, -
Environment
��- 8
.
��8 9
EnvironmentName
��9 H
}
��H I
"
��I J
)
��J K
;
��K L
app
�� 
.
�� 

UseSwagger
�� 
(
�� 
)
�� 
;
�� 
app
�� 
.
�� 
UseSwaggerUI
�� 
(
�� 
c
�� 
=>
�� 
{
�� 
c
�� 	
.
��	 

SwaggerEndpoint
��
 
(
�� 
$str
�� 4
,
��4 5
$str
��6 A
)
��A B
;
��B C
c
�� 	
.
��	 

RoutePrefix
��
 
=
�� 
string
�� 
.
�� 
Empty
�� $
;
��$ %
}
�� 
)
�� 
;
�� 
}�� 
app�� 
.
�� 
UseAuthentication
�� 
(
�� 
)
�� 
;
�� 
app�� 
.
�� 
UseAuthorization
�� 
(
�� 
)
�� 
;
�� 
app�� 
.
�� 
UseMiddleware
�� 
<
�� )
ExceptionHandlingMiddleware
�� -
>
��- .
(
��. /
)
��/ 0
;
��0 1
app�� 
.
�� 
UseMiddleware
�� 
<
�� #
DevelopmentMiddleware
�� '
>
��' (
(
��( )
)
��) *
;
��* +
app�� 
.
�� 
UseMiddleware
�� 
<
�� '
SecurityHeadersMiddleware
�� +
>
��+ ,
(
��, -
)
��- .
;
��. /
app�� 
.
�� 
UseWhen
�� 
(
�� 
ctx
�� 
=>
�� 
ctx
��	 
.
�� 
Request
�� 
.
�� 
Path
�� 
.
��  
StartsWithSegments
�� ,
(
��, -
$str
��- <
)
��< =
&&
��> @
ctx
��A D
.
��D E
Request
��E L
.
��L M
Method
��M S
==
��T V
$str
��W ]
,
��] ^
pr
�� 
=>
�� 
pr
�� 

.
��
 
UseMiddleware
�� 
<
�� 
ApiKeyMiddleware
�� )
>
��) *
(
��* +
)
��+ ,
)�� 
;
�� 
app�� 
.
�� 
MapControllers
�� 
(
�� 
)
�� 
;
�� 
app�� 
.
�� 
Run
�� 
(
�� 
)
�� 	
;
��	 
�
�C:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Middlewares\SecurityHeadersMiddleware.cs
	namespace 	
DICREP
 
. 
EcommerceSubastas "
." #
API# &
.& '
Middlewares' 2
{ 
public 

class %
SecurityHeadersMiddleware *
{ 
private 
readonly 
RequestDelegate (
_next) .
;. /
public %
SecurityHeadersMiddleware (
(( )
RequestDelegate) 8
next9 =
)= >
{ 	
_next		 
=		 
next		 
;		 
}

 	
public 
async 
Task 
Invoke  
(  !
HttpContext! ,
context- 4
)4 5
{ 	
context 
. 
Response 
. 
Headers $
.$ %
Add% (
(( )
$str) B
,B C
$strD Y
)Y Z
;Z [
context 
. 
Response 
. 
Headers $
.$ %
Add% (
(( )
$str) D
,D E
$strF t
)t u
;u v
context 
. 
Response 
. 
Headers $
.$ %
Add% (
(( )
$str) A
,A B
$strC L
)L M
;M N
if 
( 
! 
context 
. 
Response !
.! "
Headers" )
.) *
ContainsKey* 5
(5 6
$str6 G
)G H
)H I
{ 
context 
. 
Response  
.  !
Headers! (
.( )
Add) ,
(, -
$str- >
,> ?
$str@ F
)F G
;G H
} 
context 
. 
Response 
. 
Headers $
.$ %
Add% (
(( )
$str) :
,: ;
$str< I
)I J
;J K
context 
. 
Response 
. 
Headers $
.$ %
Add% (
(( )
$str) =
,= >
$str? i
)i j
;j k
await 
_next 
( 
context 
)  
;  !
} 	
} 
}   �*
�C:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Middlewares\ExceptionHandlingMiddleware.cs
	namespace 	
DICREP
 
. 
EcommerceSubastas "
." #
API# &
.& '
Middlewares' 2
{ 
public 

class '
ExceptionHandlingMiddleware ,
{ 
private 
readonly 
RequestDelegate (
_next) .
;. /
private 
readonly 
ILogger  
<  !'
ExceptionHandlingMiddleware! <
>< =
_logger> E
;E F
public

 '
ExceptionHandlingMiddleware

 *
(

* +
RequestDelegate

+ :
next

; ?
,

? @
ILogger

A H
<

H I'
ExceptionHandlingMiddleware

I d
>

d e
logger

f l
)

l m
{ 	
_next 
= 
next 
; 
_logger 
= 
logger 
; 
} 	
public 
async 
Task 
Invoke  
(  !
HttpContext! ,
context- 4
)4 5
{ 	
try 
{ 
await 
_next 
( 
context #
)# $
;$ %
} 
catch 
( #
DatosFaltantesException *
ex+ -
)- .
{ 
_logger 
. 

LogWarning "
(" #
ex# %
.% &
Message& -
)- .
;. /
context 
. 
Response  
.  !

StatusCode! +
=, -
StatusCodes. 9
.9 :
Status400BadRequest: M
;M N
await 
context 
. 
Response &
.& '
WriteAsJsonAsync' 7
(7 8
new8 ;
{< =
error> C
=D E
exF H
.H I
MessageI P
}Q R
)R S
;S T
} 
catch 
( #
EntityNotFoundException *
ex+ -
)- .
{   
_logger!! 
.!! 

LogWarning!! "
(!!" #
ex!!# %
.!!% &
Message!!& -
)!!- .
;!!. /
context"" 
."" 
Response""  
.""  !

StatusCode""! +
="", -
StatusCodes"". 9
.""9 :
Status404NotFound"": K
;""K L
await## 
context## 
.## 
Response## &
.##& '
WriteAsJsonAsync##' 7
(##7 8
new##8 ;
{##< =
error##> C
=##D E
ex##F H
.##H I
Message##I P
}##Q R
)##R S
;##S T
}$$ 
catch%% 
(%% (
EntityAlreadyExistsException%% /
ex%%0 2
)%%2 3
{&& 
_logger'' 
.'' 

LogWarning'' "
(''" #
ex''# %
.''% &
Message''& -
)''- .
;''. /
context(( 
.(( 
Response((  
.((  !

StatusCode((! +
=((, -
StatusCodes((. 9
.((9 :
Status409Conflict((: K
;((K L
await)) 
context)) 
.)) 
Response)) &
.))& '
WriteAsJsonAsync))' 7
())7 8
new))8 ;
{))< =
error))> C
=))D E
ex))F H
.))H I
Message))I P
}))Q R
)))R S
;))S T
}** 
catch++ 
(++ '
InvalidCredentialsException++ -
ex++. 0
)++0 1
{,, 
_logger-- 
.-- 

LogWarning-- "
(--" #
ex--# %
.--% &
Message--& -
)--- .
;--. /
context.. 
... 
Response..  
...  !

StatusCode..! +
=.., -
StatusCodes... 9
...9 :!
Status401Unauthorized..: O
;..O P
await// 
context// 
.// 
Response// &
.//& '
WriteAsJsonAsync//' 7
(//7 8
new//8 ;
{//< =
error//> C
=//D E
ex//F H
.//H I
Message//I P
}//Q R
)//R S
;//S T
}00 
catch11 
(11 
	Exception11 
ex11 
)11  
{22 
_logger33 
.33 
LogError33  
(33  !
ex33! #
,33# $
$str33% D
)33D E
;33E F
context44 
.44 
Response44  
.44  !

StatusCode44! +
=44, -
StatusCodes44. 9
.449 :(
Status500InternalServerError44: V
;44V W
await55 
context55 
.55 
Response55 &
.55& '
WriteAsJsonAsync55' 7
(557 8
new558 ;
{55< =
error55> C
=55D E
$str55F p
+55p q
ex55q s
.55s t
Message55t {
}55| }
)55} ~
;55~ 
}66 
}77 	
}88 
}:: �
�C:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Middlewares\DevelopmentMiddleware.cs
	namespace 	
DICREP
 
. 
EcommerceSubastas "
." #
API# &
.& '
Middlewares' 2
{ 
public 

class !
DevelopmentMiddleware &
{ 
private		 
readonly		 
RequestDelegate		 (
_next		) .
;		. /
private

 
readonly

 
IHostEnvironment

 )
_env

* .
;

. /
public !
DevelopmentMiddleware $
($ %
RequestDelegate% 4
next5 9
,9 :
IHostEnvironment; K
envL O
)O P
{ 	
_next 
= 
next 
; 
_env 
= 
env 
; 
} 	
public 
async 
Task 
InvokeAsync %
(% &
HttpContext& 1
context2 9
)9 :
{ 	
var 
endpoint 
= 
context "
." #
GetEndpoint# .
(. /
)/ 0
;0 1
if 
( 
endpoint 
? 
. 
Metadata "
." #
GetMetadata# .
<. /$
DevelopmentOnlyAttribute/ G
>G H
(H I
)I J
!=K M
nullN R
&& 
_env 
. 
EnvironmentName '
!=( *
$str+ 8
)8 9
{ 
context 
. 
Response  
.  !

StatusCode! +
=, -
StatusCodes. 9
.9 :
Status404NotFound: K
;K L
return 
; 
} 
await 
_next 
( 
context 
)  
;  !
} 	
}   
}!! �
�C:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Middlewares\ApiKeyMiddleware.cs
	namespace 	
DICREP
 
. 
EcommerceSubastas "
." #
API# &
.& '
Middlewares' 2
{ 
public 

class 
ApiKeyMiddleware !
{ 
private 
readonly 
RequestDelegate (
_next) .
;. /
public 
ApiKeyMiddleware 
(  
RequestDelegate  /
next0 4
,4 5
IApiKeyValidation6 G
	validatorH Q
)Q R
{		 	
_next

 
=

 
next

 
;

 
	Validator 
= 
	validator !
;! "
} 	
public 
IApiKeyValidation  
	Validator! *
{+ ,
get- 0
;0 1
}2 3
public 
async 
Task 
InvokeAsync %
(% &
HttpContext& 1
ctx2 5
)5 6
{ 	
if 
( 
! 
ctx 
. 
Request 
. 
Headers $
.$ %
TryGetValue% 0
(0 1
	Constants1 :
.: ;
ApiKeyHeaderName; K
,K L
outM P
varQ T
keyU X
)X Y
||Z \
! 
	Validator 
. 
IsValid "
(" #
key# &
)& '
)' (
{ 
ctx 
. 
Response 
. 

StatusCode '
=( )
key* -
.- .
Count. 3
==4 6
$num7 8
?9 :
StatusCodes; F
.F G
Status400BadRequestG Z
:[ \
StatusCodes] h
.h i!
Status401Unauthorizedi ~
;~ 
return 
; 
} 
await 
_next 
( 
ctx 
) 
; 
} 	
} 
} �
�C:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Controllers\ReceiveFichaProducto.cs
	namespace

 	
DICREP


 
.

 
EcommerceSubastas

 "
.

" #
API

# &
.

& '
Controllers

' 2
{ 
[ 
Route 

(
 
$str 
) 
] 
[ 
ApiController 
] 
public 

class  
ReceiveFichaProducto %
:& '
ControllerBase( 6
{ 
private 
readonly 
ReceiveFichaUseCase , 
_receiveFichaUseCase- A
;A B
public  
ReceiveFichaProducto #
(# $
ReceiveFichaUseCase% 8#
receivePrendasCLUseCase9 P
)P Q
{ 	 
_receiveFichaUseCase  
=! "#
receivePrendasCLUseCase# :
;: ;
} 	
[ 	
AllowAnonymous	 
] 
[ 	
HttpPost	 
( 
$str (
)( )
]) *
public 
async 
Task 
< 
ActionResult &
<& '
ResponseDTO' 2
<2 3
int3 6
>6 7
>7 8
>8 9$
ReceiveFichaProductoPOST: R
(R S
ReceiveFichaDtoS b
dtoc f
)f g
{ 	
var 
prendas 
= 
await  
_receiveFichaUseCase  4
.4 5
ExecuteAsync5 A
(A B
dtoB E
)E F
;F G
return 
prendas 
; 
}   	
}## 
}$$ �
�C:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Controllers\AccesoController.cs
	namespace 	
DICREP
 
. 
EcommerceSubastas "
." #
API# &
.& '
Controllers' 2
{		 
[

 
DevelopmentOnly

 
]

 
[ 
Route 

(
 
$str 
) 
] 
[ 
ApiController 
] 
public 

class 
AccesoController !
:" #
ControllerBase$ 2
{ 
private 
readonly (
GetAllFuncionalidadesUseCase 5)
_getAllFuncionalidadesUseCase6 S
;S T
private 
readonly !
GetAllPermisosUseCase ."
_getAllPermisosUseCase/ E
;E F
public 
AccesoController 
(  (
GetAllFuncionalidadesUseCase  <(
getAllFuncionalidadesUseCase= Y
,Y Z!
GetAllPermisosUseCase[ p"
getAllPermisosUseCase	q �
)
� �
{ 	)
_getAllFuncionalidadesUseCase )
=* +(
getAllFuncionalidadesUseCase, H
;H I"
_getAllPermisosUseCase "
=# $!
getAllPermisosUseCase% :
;: ;
} 	
}(( 
})) �
�C:\Users\sawad\Downloads\repositorios_gitlab_dicrep\api_remates_fase1\DICREP.EcommerceSubastas.API\Attributes\DevelopmentOnlyAttribute.cs
	namespace 	
DICREP
 
. 
EcommerceSubastas "
." #
API# &
.& '

Attributes' 1
{ 
[ 
AttributeUsage 
( 
AttributeTargets $
.$ %
Class% *
|+ ,
AttributeTargets- =
.= >
Method> D
)D E
]E F
public 

class $
DevelopmentOnlyAttribute )
:* +
	Attribute, 5
{ 
}

 
} 