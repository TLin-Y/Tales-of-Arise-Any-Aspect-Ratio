#include "stdafx.h"
#include "version.h"
#include "helper.hpp"

#ifdef _DEBUG
    #define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#else
    #define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO
#endif

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <safetyhook.hpp>
#include <inipp/inipp.h>

HMODULE exeModule = GetModuleHandle(NULL);
HMODULE thisModule;

std::shared_ptr<spdlog::logger> logger;
std::string sLogFile = "ToA_ARFix.log";
std::filesystem::path ExePath;
std::string sExeName;

inipp::Ini<char> ini;
std::string sConfigFile = "ToA_ARFix.ini";
std::filesystem::path FixPath;

float fTargetWidth = 4.0f;
float fTargetHeight = 3.0f;
float fTargetRatio = 1.3333333f;

template<typename T>
T GetConfigAndLog(inipp::Ini<char>& ini, const std::string& section, const std::string& key, T defaultValue) {
    T value = defaultValue;
    inipp::get_value(ini.sections[section], key, value);
    SPDLOG_INFO("Config Parse: [{}]: {} = {}", section, key, value);
    return value;
}

void Logging() {
    WCHAR dllPath[_MAX_PATH] = {0};
    GetModuleFileNameW(thisModule, dllPath, MAX_PATH);
    FixPath = dllPath;
    FixPath = FixPath.remove_filename();
    
    WCHAR gameExePath[_MAX_PATH] = {0};
    GetModuleFileNameW(exeModule, gameExePath, MAX_PATH);
    ExePath = gameExePath;
    sExeName = ExePath.filename().string();
    ExePath = ExePath.remove_filename();

    try {
        std::ofstream file(ExePath / sLogFile, std::ios::trunc);
        if (file.is_open()) file.close();
        logger = std::make_shared<spdlog::logger>("ToA_ARFix", std::make_shared<spdlog::sinks::rotating_file_sink_st>((ExePath / sLogFile).string(), 10 * 1024 * 1024, 1));
        spdlog::set_default_logger(logger);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v");
        spdlog::flush_on(spdlog::level::debug);
        spdlog::set_level(spdlog::level::debug); 
        SPDLOG_INFO("----------");
        SPDLOG_INFO("Tales of Arise AR Fix Initialized");
        SPDLOG_INFO("----------");
    }
    catch (const spdlog::spdlog_ex &ex) {}
}

void Configuration() {
    std::ifstream iniFile(FixPath / sConfigFile);
    if (!iniFile) {
        SPDLOG_WARN("Could not locate {}. Using default 4:3.", sConfigFile);
        fTargetRatio = 4.0f / 3.0f;
        return;
    }
    ini.parse(iniFile);
    ini.strip_trailing_comments();
    
    fTargetWidth = GetConfigAndLog(ini, "AspectRatio", "TargetWidth", 4.0f);
    fTargetHeight = GetConfigAndLog(ini, "AspectRatio", "TargetHeight", 3.0f);

    if (fTargetHeight > 0.001f) {
        fTargetRatio = fTargetWidth / fTargetHeight;
    }
    SPDLOG_INFO("Calculated Target Ratio: {}", fTargetRatio);
}

void ApplyHooks() {
    std::uint8_t* ARScanResult = Memory::PatternScan(exeModule, "F3 0F 11 47 18 8B 83 60 02 00 00 89 47 2C 8B 83 64 02 00 00");
    
    if (ARScanResult) {
        SPDLOG_INFO("ToA AR Fix: Found instruction pattern! Hooking...");
        
        static SafetyHookMid ARMidHook{};
        ARMidHook = safetyhook::create_mid(ARScanResult + 11,
            [](SafetyHookContext& ctx) {
                *(float*)&ctx.rax = fTargetRatio;
            });
    }
    else {
        SPDLOG_ERROR("ToA AR Fix: Pattern scan failed.");
    }
}

DWORD __stdcall Main(void*) {
    Logging();
    Configuration();
    
    Sleep(3000); 
    
    ApplyHooks();
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        thisModule = hModule;
        if (HANDLE mainHandle = CreateThread(NULL, 0, Main, 0, NULL, 0)) {
            SetThreadPriority(mainHandle, THREAD_PRIORITY_HIGHEST);
            CloseHandle(mainHandle);
        }
    }
    return TRUE;
}