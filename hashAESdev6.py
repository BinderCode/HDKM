#随机选取读取多个图片，v6去除了打印输出  最后要删除picen加密文件
#加入ORAM  ORAM每次读取完后PM随机打乱顺序
#
import hashlib
import os
from Crypto.Cipher import AES
import time
from Crypto.Util.Padding import pad, unpad
import random
import shutil

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256  # 引入 SHA256 算法实例

def update_aes_key(prev_hash, aes_key):
    # 通过 HKDF 使用 prev_hash 和 aes_key 生成新的密钥
    new_key = HKDF(prev_hash + aes_key, 32, salt=None, hashmod=SHA256)  # 使用 SHA256 算法实例
    return new_key

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

def decrypt_image(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)  # 从文件中读取IV
        encrypted_data = f.read()
    cipher = AES.new(key[:16], AES.MODE_CBC, iv) # 使用完整的 aes_key 而不是 aes_key[:16]
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    output_path = os.path.join('picde', os.path.basename(file_path).replace('.encrypted', ''))
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

# 全局变量 matrix 和 already_read 用于在多次调用中保持状态
matrix = []
already_read = []
def DORAM(total_files, max_index, i):
    """
    模拟 ORAM 或 PathORAM 的读取策略，结合行列矩阵的读取和随机选择策略。
    增强功能：1. 每次读取后从 `matrix` 中删除已读取的行。
             2. 对剩余的 `matrix` 行进行随机打乱。
    参数：
    - total_files: 总文件数，用于生成矩阵
    - max_index: 每行的最大元素数
    - i: 当前调用的次数
    """
    global matrix  # 使用全局变量保持矩阵状态

    # 第一次调用，初始化矩阵
    if i == 0:
        # Step 1: 生成包含 0 到 total_files - 1 数值且不重复的二维数组（矩阵）
        all_numbers = list(range(total_files))
        random.shuffle(all_numbers)  # 打乱所有数字的顺序
        matrix = [all_numbers[j * max_index:(j + 1) * max_index] for j in range((total_files + max_index - 1) // max_index)]
        # 如果最后一行不足 max_index，则补充随机数（保证每行长度一致）
        if len(matrix[-1]) < max_index:
            remaining_numbers = list(set(range(total_files)) - set(all_numbers))
            while len(matrix[-1]) < max_index:
                matrix[-1].append(remaining_numbers.pop() if remaining_numbers else random.randint(0, total_files - 1))
    # 如果矩阵为空，说明所有行均已读取
    if not matrix:
        print("所有行数据均已被读取！")
        return None

    # Step 2: 随机选择一行，并从矩阵中删除该行
    readrow = random.randrange(len(matrix))  # 随机选择一个行索引
    row_data = matrix.pop(readrow)  # 从矩阵中删除选中的行并获取该行数据

    # Step 3: 随机打乱剩余的矩阵
    random.shuffle(matrix)  # 打乱矩阵中剩余行的顺序
    # 返回读取的行（排序后）
    return sorted(row_data)

def process_decrypt_images_in_folder(folder_path, total_files, max_index):
    if not os.path.exists('picde'):
        os.makedirs('picde')
    aes_key = b'v \xf35$\x90{\xbd-\xa2v\xc3\xbf\xb0\xf3\xa3'
    iv = b'initialvector123'  # 固定IV值，确保加密/解密一致
    prev_hash = ''
    count=0
    while True:
        # 随机生成ORAMbuf数组并写入status.txt
        ORAMbuf = DORAM(total_files, max_index, count)
        count+=1
        #print(f"生成的 ORAMbuf 数组: {ORAMbuf}")
        if ORAMbuf is None:
            break
        # 随机选择一个ORAMbuf中的文件编号并写入status.txt
        random_file_index = random.choice(ORAMbuf)  # 随机选择一个元素
        random_file_index_position = ORAMbuf.index(random_file_index)  # 获取该元素在 ORAMbuf 中的索引
        #print(f"随机选取的文件编号: {random_file_index}")
        # 将 prev_hash 转换为十六进制字符串（假设 prev_hash 是字节类型）
        prev_hash_str = prev_hash.hex() if prev_hash else ''  # 如果 prev_hash 为 None 或空，使用空字符串
        # 合并文件编号和状态信息为一个字符串
        status_message = f"selected_file={random_file_index}|status=1|ORAMbuf={ORAMbuf}|{prev_hash_str}"
        # 将该文件编号和状态信息写入status.txt
        status_encrypted = encrypt_status(status_message, aes_key[:16], iv)
        with open('status.txt', 'wb') as status_file:
            status_file.write(status_encrypted)

        # 等待加密程序处理完并返回
        while True:
            if os.path.exists('status.txt'):
                with open('status.txt', 'rb') as status_file:
                    encrypted_status = status_file.read()
                try:
                    status = decrypt_status(encrypted_status, aes_key[:16], iv)
                except Exception as e:
                    print(f"解密 status.txt 时出错: {e}")
                    status = None

                if status == '1':  # 加密程序已处理完成，继续解密
                    print("加密程序已处理完成，继续解密。")
                    break
                elif status == 'end':
                    print("接收到结束信号，解密程序结束。")
                    os.remove('status.txt')  # 删除结束信号文件
                    return
                else:
                    time.sleep(0.1)
            else:
                time.sleep(0.1)  # 如果没有status.txt文件，继续等待

        # 获取所有加密文件的列表并选择对应的文件
        encrypted_files = sorted([f for f in os.listdir(folder_path) if f.lower().endswith('.encrypted')])
        #print("encrypted_files=",encrypted_files)
        if not encrypted_files:
            print("没有加密文件，等待加密程序发信号。")
            time.sleep(1)
            continue

        for index, file in enumerate(encrypted_files):  #enumerate() 返回一个包含索引和元素的元组 (index, file)
        # 如果有加密文件，处理一张
            file_path = os.path.join(folder_path, file)
            # 更新解密密钥
            if not prev_hash:
                decrypt_key = aes_key
            else:
                decrypt_key = update_aes_key(prev_hash,aes_key)

            # 解密图片
            decrypt_image(file_path, decrypt_key)
            # 删除已解密的加密文件
            os.remove(file_path)
            # 更新哈希值作为下一张图片的密钥一部分
            prev_image_path = os.path.join('picde', os.path.basename(file).replace('.encrypted', ''))
            if index==random_file_index_position:
                hash_dir=prev_image_path        #保存对应图片具体位置
        prev_hash = get_image_hash(hash_dir).encode('utf-8')


if __name__ == "__main__":
    import csv
    # 定义测试参数
    total_files_list = [512, 1024, 2048, 4096, 8192]  # 总的文件数量512, 1024, 2048, 4096,
    max_index_list = [64]      # ORAMbuf数组长度

    # CSV 文件路径
    csv_file_path = "Cifar_entimes.csv"

    # 准备 CSV 文件
    with open(csv_file_path, mode='w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # 写入表头
        csv_writer.writerow(["Total Files", "Max Index", "Decryption Time (s)"])

        for total_files in total_files_list:
            for max_index in max_index_list:
                print(f"正在测试：Total Files = {total_files}, Max Index = {max_index}")

                # 指定加密和解密的路径
                #input_folder = "E:\\data\\cifar-100\\train\\cifar100"           # 加密输入文件夹路径 (需要用户自行准备)
                encrypted_folder = "picen"    # 加密后的输出文件夹路径

                # 2. 测量解密时间
                start_time = time.time()
                process_decrypt_images_in_folder(encrypted_folder, total_files, max_index)
                end_time = time.time()
                decryption_time = end_time - start_time
                print(f"解密完成，运行时间是: {decryption_time} 秒")

                # 3. 删除加密文件夹
                #shutil.rmtree(encrypted_folder)

                # 4. 将结果保存到 CSV 文件
                csv_writer.writerow([total_files, max_index, decryption_time])

    print(f"测试完成，结果已保存到 CSV 文件：{csv_file_path}")
