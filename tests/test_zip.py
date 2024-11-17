import unittest
from zippy.exceptions import *
from zippy import ZipFile
from zippy.compressions import *

from os import chdir
try:
    chdir('.\\zip_files')
except FileNotFoundError:
    chdir('.\\tests\\zip_files\\')

class TestCase1(unittest.TestCase):

    def setUp(self) -> None:
        self.test_str: str = 'Lorem ipsum dolor sit amet. Id eveniet omnis vel magnam molestiae eum maxime dolor ad ipsam veritatis a voluptas expedita et galisum expedita est suscipit soluta. Et iure quasi nam ullam eius et voluptatem galisum ea corporis pariatur et aliquid tenetur eum dolorum corporis hic consequatur esse. Qui velit adipisci sed magni dolor id nobis eveniet non sunt ipsa rem nobis nesciunt? Aut voluptas error hic rerum deserunt a sequi quidem ab quam cupiditate est deserunt quasi ad eveniet maiores sit sequi esse! Ea dolores voluptates sit debitis provident aut architecto dignissimos non itaque voluptatibus sit quia recusandae vel aliquam galisum. Quo cumque omnis ab rerum consequatur et cumque consectetur et dolorem nihil. At enim dolorem sit voluptates quia est voluptatibus dolore est consequuntur quasi qui nostrum voluptatem. Qui quasi magni id perferendis sequi aut voluptatem dicta. Eos eaque omnis sit natus molestias ab aliquid ratione sed dolor quia ut galisum molestias sit iste totam. Qui ipsa quasi ad fugit nihil ut necessitatibus unde aut numquam error. 33 commodi deleniti aut consequatur eius aut rerum tempora? Est consequatur magnam et adipisci minima 33 similique eligendi non dolor aperiam aut molestiae eius? Sit nostrum consequatur qui mollitia vero est esse aperiam quo repellat velit sit saepe soluta sed recusandae fuga in sunt enim. Hic unde officiis ut dolores soluta ut atque accusamus ad veritatis placeat qui velit atque qui delectus perferendis qui voluptate provident. Ab deserunt laborum cum possimus provident non molestias magni et quidem minus? Ut eaque culpa cum corporis vitae et similique perspiciatis eum illo praesentium a adipisci quaerat est modi nemo. Ut eligendi necessitatibus non mollitia aliquam ex nostrum perferendis eos modi praesentium vel quia omnis. Et nesciunt aliquam rem eius inventore aut distinctio esse ut excepturi amet a placeat asperiores sed culpa eius est recusandae iure. Et aspernatur facere id excepturi sapiente aut corrupti pariatur et atque laborum 33 consequatur iure aut sint consequatur. Eum exercitationem illum qui modi voluptas non dicta quisquam ea debitis commodi et nobis quia. Sit ipsa voluptatem nam perspiciatis iusto ut molestias maxime aut quam saepe ea consequatur minus. Ut tempore error et voluptates perferendis ea iure dolorum qui consequatur dolores. Rem nihil esse aut tenetur libero qui incidunt voluptas ut fugit repellendus ut ratione labore. Et facilis iusto nam voluptatum unde eum quibusdam voluptatem ut nihil temporibus et accusantium voluptatem et vitae quibusdam qui blanditiis tenetur. Quo quis omnis a tenetur nemo est porro nulla et itaque ipsum vel iusto dignissimos qui incidunt consequuntur sed explicabo nihil.'

    def test_decompression(self) -> None:
        with ZipFile.open('stored.zip') as z:
            self.assertEqual(self.test_str, z._files[0].peek())

        with ZipFile.open('deflate.zip') as z:  # Includes deflate64
            self.assertEqual(self.test_str, z._files[0].peek())

        with ZipFile.open('BZip2.zip') as z:
            self.assertEqual(self.test_str, z._files[0].peek())

    def test_decryption(self) -> None:
        with ZipFile.open('ZipEncrypted.zip', 'verysecurepassword') as z:
            self.assertEqual(self.test_str, z._files[0].peek())

        self.assertRaises(WrongPassword, lambda: ZipFile.open('ZipEncrypted.zip', 'wrongpassword'))

    def test_exctract(self) -> None:  # This test should finish without exceptions (os exceptions mainly)
        with ZipFile.open('folders.zip') as z:
            z.extract_all()

    def test_create_folder(self) -> None:
        z = ZipFile.new()
        z.create_folder('test1\\test2')
        self.assertEqual(['test1/', 'test1/test2/'], list(z._files.keys()))

    def test_new(self) -> None:
        zipfile = ZipFile.new()
        zipfile.create_file(
            'lorem ipsum.txt',
            self.test_str,
            compression=DEFLATE,
            level=MAXIMUM,
            comment='LOREM'
        )
        zipfile.add_file(
            'lorem.txt',
            'lorem ipsum.txt',
            compression=DEFLATE64,
            level=MAXIMUM,
            comment='LOREM2'
        )
        zipfile.save('new.zip', comment='Lorem')

        with ZipFile.open('new.zip') as z:
            self.assertEqual(self.test_str, z._files[0].peek())
            self.assertEqual('Lorem', z._comment)
            self.assertEqual('LOREM2', z._files[0].comment)  # Replacing already existing file check

        zipfile = ZipFile.new()
        zipfile.create_file('test1\\test2\\test.txt', 'TEXT')
        self.assertEqual(['test1\\', 'test1\\test2\\', 'test1\\test2\\test.txt'], zipfile.get_structure())
        zipfile.remove('test1\\test2\\test.txt')
        self.assertEqual(['test1\\', 'test1\\test2\\'], zipfile.get_structure())
        zipfile.create_file('test1\\test2\\test.txt', 'TEXT')
        zipfile.remove('test1\\test2')
        self.assertEqual(['test1\\'], zipfile.get_structure())

    def test_add_from_archive(self) -> None:
        z = ZipFile.new()
        z.add_from_archive('folders.zip', 'goodbyedpi-0.2.2\\', 'EXTRA FOLDER')
        struct = ['EXTRA FOLDER\\', 'EXTRA FOLDER\\0_russia_update_blacklist_file.cmd', 'EXTRA FOLDER\\1_russia_blacklist.cmd', 'EXTRA FOLDER\\1_russia_blacklist_dnsredir.cmd', 'EXTRA FOLDER\\2_any_country.cmd', 'EXTRA FOLDER\\2_any_country_dnsredir.cmd', 'EXTRA FOLDER\\licenses\\', 'EXTRA FOLDER\\licenses\\LICENSE-getline.txt', 'EXTRA FOLDER\\licenses\\LICENSE-goodbyedpi.txt', 'EXTRA FOLDER\\licenses\\LICENSE-uthash.txt', 'EXTRA FOLDER\\licenses\\LICENSE-windivert.txt', 'EXTRA FOLDER\\licenses\\test.zip', 'EXTRA FOLDER\\russia-blacklist.txt', 'EXTRA FOLDER\\service_install_russia_blacklist.cmd', 'EXTRA FOLDER\\service_install_russia_blacklist_dnsredir.cmd', 'EXTRA FOLDER\\service_remove.cmd', 'EXTRA FOLDER\\x86\\', 'EXTRA FOLDER\\x86\\WinDivert.dll', 'EXTRA FOLDER\\x86\\WinDivert32.sys', 'EXTRA FOLDER\\x86\\WinDivert64.sys', 'EXTRA FOLDER\\x86\\goodbyedpi.exe', 'EXTRA FOLDER\\x86_64\\', 'EXTRA FOLDER\\x86_64\\WinDivert.dll', 'EXTRA FOLDER\\x86_64\\WinDivert64.sys', 'EXTRA FOLDER\\x86_64\\goodbyedpi.exe']
        self.assertEqual(struct, z.get_structure())

    def test_edit_file(self) -> None:
        z = ZipFile.new()
        z.create_file('test1\\test.txt', 'TEXT')
        z.edit_file('test1\\test.txt', 'NEW TEXT')
        self.assertEqual(b'NEW TEXT', z._files['test1/test.txt'].contents)
        self.assertRaises(FileNotFound, lambda: z.edit_file('test1\\nonexistent.txt', 'TEXT'))

    def test_invalid_paths(self) -> None:
        z = ZipFile.new()
        self.assertRaises(FileNotFound, lambda: z.add_file('invalid\\path\\test.txt', 'test.txt'))
        self.assertRaises(FileNotFound, lambda: z.remove('invalid\\path\\test'))
        self.assertRaises(FileNotFound, lambda: z.get_structure('invalid\\path'))

class TestCase2(unittest.TestCase):

    def test_add_directory(self) -> None:
        z = ZipFile.new()
        z.add_folder('goodbyedpi-0.2.2', 'EXTRA FOLDER')
        struct = ['EXTRA FOLDER\\', 'EXTRA FOLDER\\0_russia_update_blacklist_file.cmd', 'EXTRA FOLDER\\1_russia_blacklist.cmd', 'EXTRA FOLDER\\1_russia_blacklist_dnsredir.cmd', 'EXTRA FOLDER\\2_any_country.cmd', 'EXTRA FOLDER\\2_any_country_dnsredir.cmd', 'EXTRA FOLDER\\licenses\\', 'EXTRA FOLDER\\licenses\\LICENSE-getline.txt', 'EXTRA FOLDER\\licenses\\LICENSE-goodbyedpi.txt', 'EXTRA FOLDER\\licenses\\LICENSE-uthash.txt', 'EXTRA FOLDER\\licenses\\LICENSE-windivert.txt', 'EXTRA FOLDER\\licenses\\test.zip', 'EXTRA FOLDER\\russia-blacklist.txt', 'EXTRA FOLDER\\service_install_russia_blacklist.cmd', 'EXTRA FOLDER\\service_install_russia_blacklist_dnsredir.cmd', 'EXTRA FOLDER\\service_remove.cmd', 'EXTRA FOLDER\\x86\\', 'EXTRA FOLDER\\x86\\WinDivert.dll', 'EXTRA FOLDER\\x86\\WinDivert32.sys', 'EXTRA FOLDER\\x86\\WinDivert64.sys', 'EXTRA FOLDER\\x86\\goodbyedpi.exe', 'EXTRA FOLDER\\x86_64\\', 'EXTRA FOLDER\\x86_64\\WinDivert.dll', 'EXTRA FOLDER\\x86_64\\WinDivert64.sys', 'EXTRA FOLDER\\x86_64\\goodbyedpi.exe']
        self.assertEqual(struct, z.get_structure())

if __name__ == '__main__':
    unittest.main()
