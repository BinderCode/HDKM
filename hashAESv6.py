#每次上传5张图片，然后随机生成，v4由解密程序下发解密哈希值
#新增了HKDF算法用于密钥更新  ORAM   
#v6去除了打印输出，新增删除
#测试不同数据集的时间
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import shutil  # 用于删除整个文件夹
import logging
import re
#使用 HKDF (HMAC-based Key Derivation Function)  HKDF 也是一种非常安全的密钥派生方法，它使用 HMAC（哈希消息认证码）作为基础。
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256  # 引入 SHA256 算法实例

def update_aes_key(prev_hash, aes_key):
    # 通过 HKDF 使用 prev_hash 和 aes_key 生成新的密钥
    new_key = HKDF(prev_hash + aes_key, 32, salt=None, hashmod=SHA256)  # 使用 SHA256 算法实例
    return new_key
# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 获取图片的SHA256哈希值
def get_image_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            img_data = f.read()
        hash_object = hashlib.sha256(img_data)
        return hash_object.hexdigest()
    except FileNotFoundError:
        print(f"文件 {file_path} 未找到。")
        return None
    except Exception as e:
        print(f"发生错误: {e}")
        return None

# 使用AES加密图片
def encrypt_image(file_path, key, output_folder):
    with open(file_path, 'rb') as f:
        iv = f.read(16)  # 从文件中读取IV
        img_data = f.read()
    cipher = AES.new(key[:16], AES.MODE_CBC)  # 使用前16字节的密钥
    padded_data = pad(img_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    iv = cipher.iv  # 获取生成的IV
    file_name = os.path.basename(file_path) + '.encrypted'
    output_path = os.path.join(output_folder, file_name)
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)  # 将 IV 和加密数据一起写入文件

# 加密状态文件内容
def encrypt_status(status, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_status = cipher.encrypt(pad(status.encode('utf-8'), AES.block_size))
    return encrypted_status

# 解密状态文件内容
def decrypt_status(encrypted_status, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_status = unpad(cipher.decrypt(encrypted_status), AES.block_size)
    return decrypted_status.decode('utf-8')

def process_images_in_folder(folder_path, output_folder, max_images=100):
    """
    处理文件夹中的图片，按指定的索引数组上传图片，并使用第一个图片的哈希值作为密钥更新依据。
    :param folder_path: 图片文件夹路径
    :param output_folder: 加密图片输出文件夹路径
    :param max_images: 最大处理的图片数量
    """
    # 删除输出文件夹内容
    shutil.rmtree(output_folder, ignore_errors=True)
    os.makedirs(output_folder, exist_ok=True)

    aes_key = b'v \xf35$\x90{\xbd-\xa2v\xc3\xbf\xb0\xf3\xa3'
    iv = b'initialvector123'  # 初始化向量
    image_count = 0
    prev_hash = ''  # 用于存储第一个图片的哈希值

    # 获取文件夹中的所有图片文件
    all_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
                all_files.append(os.path.join(root, file))

    # 每次从status.txt接收ORAMbuf并加密对应图片
    while image_count < max_images:
        # 等待解密程序传递 ORAMbuf
        while True:
            if os.path.exists('status.txt'):
                with open('status.txt', 'rb') as status_file:
                    encrypted_status = status_file.read()
                try:
                    status = decrypt_status(encrypted_status, aes_key[:16], iv)  #解密文件
                except Exception as e:
                    print(f"解密 status.txt 时出错: {e}")
                    status = None
                if status.startswith("selected_file="):  # 如果解密后的状态为 ORAMbuf 数组
                    #selected_file_index = int(status[14:].split("|")[0])  # 解析文件编号
                    #print(f"接收到的文件为: {status[14:]}")
                    # 使用正则表达式提取 ORAMbuf 数组
                    orambuf_match = re.search(r'ORAMbuf=\[(.*?)\]', status[14:])
                    if orambuf_match:
                        orambuf_str = orambuf_match.group(1)  # 获取 ORAMbuf 数组字符串
                        ORAMbuf = list(map(int, orambuf_str.split(',')))  # 将字符串转换为整数列表
                    else:
                        print("未能从状态中提取 ORAMbuf 数组")  #第一次没有ORAMbuf数组
                        return None, None

                    # 使用正则表达式提取 prev_hash（假设是十六进制字符串）
                    prev_hash_match = re.search(r'\|([a-fA-F0-9]+)$', status[14:])
                    if prev_hash_match:
                        prev_hash_hex = prev_hash_match.group(1)  # 提取十六进制字符串
                        try:
                            # 将十六进制字符串转换回字节数据
                            prev_hash_bytes = bytes.fromhex(prev_hash_hex)
                            #print(f"转换后的 prev_hash 字节数据: {prev_hash_bytes}")
                        except ValueError as e:
                            print(f"无法转换 prev_hash，错误: {e}")
                            prev_hash_bytes = None
                    else:
                        print("未能从状态中提取 prev_hash")
                        prev_hash_bytes = None
                    break
                elif status == 'end':
                    print("接收到结束信号，程序结束。")
                    return
                else:
                    time.sleep(0.1)
            else:
                time.sleep(0.1)
        prev_hash=prev_hash_bytes    #使用上次的数据更新密钥   第一次server没有发送ORAMbuf
        if not prev_hash:
                encrypt_key = aes_key
        else:
            encrypt_key = update_aes_key(prev_hash,aes_key)
        # 根据 ORAMbuf 中的索引进行加密
        for index in ORAMbuf:
            if image_count >= max_images:
                break
            if index < 0 or index >= len(all_files):
                #logging.warning(f"索引 {index} 超出范围，跳过。")
                continue
            file_path = all_files[index]
            # 加密图片
            encrypt_image(file_path, encrypt_key, output_folder)
            #logging.info(f"图片 {file_path} 已加密。")
            image_count += 1

        status_encrypted = encrypt_status("1", aes_key[:16], iv)
        with open('status.txt', 'wb') as status_file:
            status_file.write(status_encrypted)

    # 所有图片加密完成，发送结束信号
    #logging.info(f"已处理 {image_count} 张图片。")
    encrypted_end_signal = encrypt_status("end", aes_key[:16], iv)
    with open('status.txt', 'wb') as status_file:
        status_file.write(encrypted_end_signal)

if __name__ == "__main__":
    import csv
    # 定义测试参数
    total_files_list = [512, 1024, 2048, 4096, 8192]  # 总的文件数量512, 1024, 2048, 4096,
    max_index_list = [64]      # ORAMbuf数组长度
    # CSV 文件路径
    csv_file_path = "Cifar_detimes.csv"

    # 准备 CSV 文件
    with open(csv_file_path, mode='w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # 写入表头
        csv_writer.writerow(["Total Files", "Max Index", "encryption Time (s)"])

        for total_files in total_files_list:
            for max_index in max_index_list:
                start_time = time.time()
                folder_path = "E:\\data\\cifar-100\\train\\cifar100"  # 需要加密图片的文件夹路径
                output_folder = 'picen'  # 存储加密图片的文件夹路径
                #max_images = total_files  # 控制加密的图片数量
                process_images_in_folder(folder_path, output_folder, total_files)
                end_time = time.time()
                time_difference = end_time - start_time
                print("运行时间是: ", time_difference)
                # 4. 将结果保存到 CSV 文件
                csv_writer.writerow([total_files, max_index, time_difference])

    print(f"测试完成，结果已保存到 CSV 文件：{csv_file_path}")

