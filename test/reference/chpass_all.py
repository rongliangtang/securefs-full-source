#!/usr/bin/env python3

"""
A binary file to create all variations of .securefs.json by calling `chpass`.
这个文件通过chpass命令，来创建某个.securefs.json的所有变体（version、pbkdf、passmode和padded的组合）
该.securefs.json的密码为abc，未使用keyfile
"""

import enum
import os
import subprocess
import shutil
import sys
import glob


# 密码输入模式枚举
# 使用@enum.unique装饰器，这样当不同名称的值重复时，就会抛出异常ValueError
@enum.unique
# 继承enum.IntEnum来派生枚举类
class SecretInputMode(enum.IntEnum):
    # 0b表示二进制
    PASSWORD = 0b1
    KEYFILE = 0b10
    PASSWORD_WITH_KEYFILE = PASSWORD | KEYFILE
    KEYFILE2 = KEYFILE | 0b1000
    PASSWORD_WITH_KEYFILE2 = PASSWORD | KEYFILE2

# 根据mode来修改new_config_filename中的密码或keyfile
# new_config_filename已经存在则返回，否则将.securefs.*.PASSWORD.json的内容复制过去
# 函数形参:后的类型表示指定函数形参类型，虽然能够指定参数类型，当输入参数类型错误不会报错
def create(
    securefs_binary: str, version: int, pbkdf: str, mode: SecretInputMode, padded: bool
):
    # 根据是否开启padded功能来决定使用reference文件夹中的哪个数据文件（加密后）
    if padded:
        # 字符串前加f表示字符串内支持大括号内的python表达式
        data_dir = f"{version}-padded"
    else:
        data_dir = str(version)
    # 根据pbkdf密钥衍生算法和mode来确定所使用配置文件的名字
    new_config_filename = os.path.join(data_dir, f".securefs.{pbkdf}.{mode.name}.json")
    # 如果配置文件存在，则提醒并返回
    if os.path.exists(new_config_filename):
        print(new_config_filename, "already exists", file=sys.stderr)
        return
    # glob.iglob(path)返回一个匹配path格式的可遍历对象
    # 使用for和next迭代器可以从这个对象中取出每项内容
    original_config_filename = next(
        glob.iglob(os.path.join(data_dir, ".securefs.*.PASSWORD.json"))
    )
    # 将original_config_filename文件复制，并命名为new_config_filename
    shutil.copy(original_config_filename, new_config_filename)
    # args[]为使用securefs的命令
    args = [
        securefs_binary,
        "chpass",
        "--oldpass",
        "abc",
        "--pbkdf",
        pbkdf,
        "--config",
        new_config_filename,
        "-r",
        "2",
    ]
    # 如果mode是KEYFILE，在args[]后加上对应参数
    if mode & SecretInputMode.KEYFILE:
        args.extend(["--newkeyfile", "keyfile"])
    # 如果mode是PASSWORD，在args[]后加上对应参数
    if mode & SecretInputMode.PASSWORD:
        args.extend(["--newpass", "abc"])
    args.append(f"{version}")
    # 生成子进程，执行args命令
    subprocess.check_call(args)


def main():
    # 设置环境变量
    # 环境变量是程序和操作系统之间的通信方式。有些字符不宜明文写进代码里，比如数据库密码，个人账户密码，如果写进自己本机的环境变量里，程序用的时候通过 os.environ.get() 取出来就行了
    os.environ["SECUREFS_ARGON2_M_COST"] = "16"
    os.environ["SECUREFS_ARGON2_P"] = "2"
    # 返回sys.argv[1]的标准路径，而非软链接所在的路径
    binary = os.path.realpath(sys.argv[1])
    # 用于改变当前工作目录到指定的路径
    # __file__表示当前python脚本运行的路径
    os.chdir(os.path.dirname(__file__))
    # 组合每种情况生成配置文件（pbkdf是password用到的衍生密钥算法）
    for version in range(1, 5):
        for pbkdf in ("scrypt", "pkcs5-pbkdf2-hmac-sha256", "argon2id"):
            for mode in SecretInputMode:
                for padded in [False, True]:
                    create(
                        binary, version=version, pbkdf=pbkdf, mode=mode, padded=padded
                    )


if __name__ == "__main__":
    main()
