// paktool: list / extract files from Unreal paks via CUE4Parse.
//   paktool list <regex>             -> prints matching virtual paths with sizes
//   paktool extract <regex> <outdir> -> writes matching raw files
//   paktool imc <regex>              -> <context>\t<action>\t<pad key> for every gamepad key of the matching
//                                       Enhanced Input mapping contexts (UE5 IMC_*.uasset)
//   <regex> may be @<file>: the pattern is read from that file
using System.Text.RegularExpressions;
using CUE4Parse.Compression;
using CUE4Parse.Encryption.Aes;
using CUE4Parse.FileProvider;
using CUE4Parse.UE4.Objects.Core.Misc;
using CUE4Parse.UE4.Versions;

// defaults = Wukong; tools/soundprep.py passes the game's own values (from its profile json) through the environment
string Paks = Environment.GetEnvironmentVariable("PAK_DIR") ?? @"C:\Program Files (x86)\Steam\steamapps\common\BlackMythWukong\b1\Content\Paks";
string KeyId = Environment.GetEnvironmentVariable("PAK_KEY_ID") ?? "wukong";
var Game = Enum.Parse<EGame>(Environment.GetEnvironmentVariable("PAK_GAME") ?? "GAME_BlackMythWukong");
// the pak key is never kept in the source: it is read from tools/config.json (local, git-ignored)
string Key = "";
for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null && Key == ""; d = d.Parent)
{
    var cfg = Path.Combine(d.FullName, "config.json");
    if (File.Exists(cfg) && System.Text.Json.JsonDocument.Parse(File.ReadAllText(cfg)).RootElement.TryGetProperty("pak_keys", out var keys)
        && keys.TryGetProperty(KeyId, out var k)) Key = k.GetString() ?? "";
}
if (Key == "" && KeyId != "none") { Console.Error.WriteLine("no pak key: copy tools/config.example.json to tools/config.json and fill pak_keys." + KeyId); Environment.Exit(2); }

// Oodle (RAD's DLL) is fetched on the player's PC, never shipped: one fixed release of WorkingRobot/OodleUE (2.9.16,
// the one CUE4Parse names), checked by SHA-256 - the zip as downloaded and the DLL as used, so a changed file is never loaded
const string OodleZip = "https://github.com/WorkingRobot/OodleUE/releases/download/2026-06-04-1357/clang-cl-x64-release.zip";
const string OodleZipSha = "37f816a3e8f5a65a11f6defc8c28c0508287602767741ba4803c6a21a62a877b";
const string OodleDllSha = "cba19529d0a3b5ec9c630e95652af01e123ae29a34a8a5f7507f5bcf23d9e82b";
static string Sha(byte[] b) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(b)).ToLowerInvariant();
string oodle = Path.Combine(AppContext.BaseDirectory, "oodle-data-shared.dll");
if (!File.Exists(oodle) || Sha(File.ReadAllBytes(oodle)) != OodleDllSha)
{
    using var http = new HttpClient();
    http.DefaultRequestHeaders.UserAgent.ParseAdd("sonmat-paktool");
    var zip = http.GetByteArrayAsync(OodleZip).GetAwaiter().GetResult();
    if (Sha(zip) != OodleZipSha) { Console.Error.WriteLine("oodle: the downloaded zip is not the expected one (SHA-256 differs), not used"); Environment.Exit(3); }
    using var za = new System.IO.Compression.ZipArchive(new MemoryStream(zip));
    using var ms = new MemoryStream();
    za.GetEntry("bin/oodle-data-shared.dll")!.Open().CopyTo(ms);
    if (Sha(ms.ToArray()) != OodleDllSha) { Console.Error.WriteLine("oodle: the DLL in the zip is not the expected one (SHA-256 differs), not used"); Environment.Exit(3); }
    File.WriteAllBytes(oodle, ms.ToArray());
}
OodleHelper.Initialize(oodle);

var provider = new DefaultFileProvider(Paks, SearchOption.AllDirectories, new VersionContainer(Game));
provider.Initialize();
if (Key != "") provider.SubmitKey(new FGuid(), new FAesKey(Key));        // PAK_KEY_ID=none: paks without a key
Console.Error.WriteLine($"mounted files: {provider.Files.Count}");

// @<file> = the pattern is in that file (thousands of exact paths do not fit on a command line)
var rx = new Regex(args[1].StartsWith('@') ? File.ReadAllText(args[1][1..]).Trim() : args[1], RegexOptions.IgnoreCase);
var hits = provider.Files.Where(kv => rx.IsMatch(kv.Key)).OrderBy(kv => kv.Key).ToList();
if (args[0] == "list")
{
    foreach (var (path, file) in hits) Console.WriteLine($"{file.Size}\t{path}");
    Console.Error.WriteLine($"matches: {hits.Count}");
}
else if (args[0] == "extract")
{
    int ok = 0;
    foreach (var (path, file) in hits)
    {
        try
        {
            var data = file.Read();
            var dst = Path.Combine(args[2], path.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
            File.WriteAllBytes(dst, data); ok++;
        }
        catch (Exception e) { Console.Error.WriteLine($"fail {path}: {e.Message}"); }
    }
    Console.Error.WriteLine($"extracted {ok}/{hits.Count}");
}
else if (args[0] == "imc")
{
    // A cooked mapping context has unversioned properties: no layout without the game's .usmap (made by running the
    // game). Its name and import tables read without one, and in the bytes each mapping's action (an import of class
    // InputAction) is followed within a few bytes by its key, an FName (index, number 0) - read so.
    provider.MappingsContainer = new NoMappings();
    foreach (var (path, file) in hits)
    {
        if (!path.EndsWith(".uasset")) continue;
        try
        {
            var pkg = (CUE4Parse.UE4.Assets.Package)provider.LoadPackage(file);
            var b = provider.Files.TryGetValue(path[..^7] + ".uexp", out var ue) ? ue.Read() : file.Read();
            var ctx = Path.GetFileNameWithoutExtension(path);
            for (int o = 0; o + 4 <= b.Length; o++)
            {
                int v = BitConverter.ToInt32(b, o);
                if (v >= 0 || -v > pkg.ImportMap.Length || pkg.ImportMap[-v - 1].ClassName.Text != "InputAction") continue;
                for (int k = o + 4; k + 8 <= b.Length && k <= o + 16; k++)
                {
                    int n = BitConverter.ToInt32(b, k);
                    if (n < 0 || n >= pkg.NameMap.Length || BitConverter.ToInt32(b, k + 4) != 0) continue;
                    var key = pkg.NameMap[n].Name;
                    if (!key.StartsWith("Gamepad_")) continue;
                    Console.WriteLine($"{ctx}\t{pkg.ImportMap[-v - 1].ObjectName.Text}\t{key}");
                    break;
                }
            }
        }
        catch (Exception e) { Console.Error.WriteLine($"fail {path}: {e.Message}"); }
    }
}

// the mapping contexts are read by their bytes, not their properties: an empty layout lets the package open
class NoMappings : CUE4Parse.MappingsProvider.AbstractTypeMappingsProvider
{
    public override CUE4Parse.MappingsProvider.TypeMappings? MappingsForGame { get; protected set; } = new();
    public override void Reload() { }
    public override void Load(string path, StringComparer? comparer = null) { }
    public override void Load(byte[] bytes, StringComparer? comparer = null) { }
}
