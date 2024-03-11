# LN882H SDK used for OpenBeken port for LN882H -> OpenLN882H

See: https://github.com/openshwprojects/OpenBK7231T_App

# Introduction to LN882H SDK

# Compilation Methods

## 1. Keil MDK

### Environment setup
Refer to `doc/LN882H Keil ARMCC开发环境搭建指导.pdf` to configure the environment

### User project selection
The user project is in `project/xxxx`. For example, open the `wifi_mcu_basic_example` subdirectory
in the Kile IDE and clik  **Compile**、**Download**、**调试** button in the interface to start the corresponding step.

## 2. CMake+GCC

### Environment setup

See `doc/lightningsemi_sdk_cross_build_setup.pdf` to configure the environment.

### User project selection
The projects are organized in `CMakeLists.txt` file, the top-level `CMakeLists.txt` selects the user project,
see the following command in the top-level `CMakeLists.txt`:


```
################################################################################
#########################   NOTE: select user project here  ####################
################################################################################
set(USER_PROJECT  wifi_mcu_basic_example)
```

### Compile and upload the user project

Build and upload actions are managed by `start_build.py`, usage is as follows:

```
    *****************************  usage  *****************************
    argv[1] -- build action, such as clean/config/build/rebuild/jflash.
    Example:
                python3   start_build.py   rebuild
    *******************************************************************
```

- Clean: `python3  start_build.py  clean`
- Configure: `python3  start_build.py  config`
- Build: `python3  start_build.py  build`
- Clean, configure, and build all in one: `python3  start_build.py  rebuild`
- Upload the image: `python3  start_build.py  jflash`
