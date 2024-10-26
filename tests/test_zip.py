import datetime
import unittest
from zippy.zipfile.exceptions import *
from zippy import ZipFile
from zippy.zipfile.compressions import *

from os import chdir
chdir('.\\zip_files')

from icecream import ic
ic.disable()

class TestCase(unittest.TestCase):

    def setUp(self):
        self.test_str: str = 'Lorem ipsum dolor sit amet. Id eveniet omnis vel magnam molestiae eum maxime dolor ad ipsam veritatis a voluptas expedita et galisum expedita est suscipit soluta. Et iure quasi nam ullam eius et voluptatem galisum ea corporis pariatur et aliquid tenetur eum dolorum corporis hic consequatur esse. Qui velit adipisci sed magni dolor id nobis eveniet non sunt ipsa rem nobis nesciunt? Aut voluptas error hic rerum deserunt a sequi quidem ab quam cupiditate est deserunt quasi ad eveniet maiores sit sequi esse! Ea dolores voluptates sit debitis provident aut architecto dignissimos non itaque voluptatibus sit quia recusandae vel aliquam galisum. Quo cumque omnis ab rerum consequatur et cumque consectetur et dolorem nihil. At enim dolorem sit voluptates quia est voluptatibus dolore est consequuntur quasi qui nostrum voluptatem. Qui quasi magni id perferendis sequi aut voluptatem dicta. Eos eaque omnis sit natus molestias ab aliquid ratione sed dolor quia ut galisum molestias sit iste totam. Qui ipsa quasi ad fugit nihil ut necessitatibus unde aut numquam error. 33 commodi deleniti aut consequatur eius aut rerum tempora? Est consequatur magnam et adipisci minima 33 similique eligendi non dolor aperiam aut molestiae eius? Sit nostrum consequatur qui mollitia vero est esse aperiam quo repellat velit sit saepe soluta sed recusandae fuga in sunt enim. Hic unde officiis ut dolores soluta ut atque accusamus ad veritatis placeat qui velit atque qui delectus perferendis qui voluptate provident. Ab deserunt laborum cum possimus provident non molestias magni et quidem minus? Ut eaque culpa cum corporis vitae et similique perspiciatis eum illo praesentium a adipisci quaerat est modi nemo. Ut eligendi necessitatibus non mollitia aliquam ex nostrum perferendis eos modi praesentium vel quia omnis. Et nesciunt aliquam rem eius inventore aut distinctio esse ut excepturi amet a placeat asperiores sed culpa eius est recusandae iure. Et aspernatur facere id excepturi sapiente aut corrupti pariatur et atque laborum 33 consequatur iure aut sint consequatur. Eum exercitationem illum qui modi voluptas non dicta quisquam ea debitis commodi et nobis quia. Sit ipsa voluptatem nam perspiciatis iusto ut molestias maxime aut quam saepe ea consequatur minus. Ut tempore error et voluptates perferendis ea iure dolorum qui consequatur dolores. Rem nihil esse aut tenetur libero qui incidunt voluptas ut fugit repellendus ut ratione labore. Et facilis iusto nam voluptatum unde eum quibusdam voluptatem ut nihil temporibus et accusantium voluptatem et vitae quibusdam qui blanditiis tenetur. Quo quis omnis a tenetur nemo est porro nulla et itaque ipsum vel iusto dignissimos qui incidunt consequuntur sed explicabo nihil.'

    def test_compression(self):
        with ZipFile.open('.\\stored.zip') as z:
            self.assertEqual(self.test_str, z.files[0].peek())

        with ZipFile.open('.\\deflate.zip') as z:  # Includes deflate64
            self.assertEqual(self.test_str, z.files[0].peek())

        with ZipFile.open('.\\BZip2.zip') as z:
            self.assertEqual(self.test_str, z.files[0].peek())

    def test_encryption(self):
        with ZipFile.open('ZipEncrypted.zip', 'verysecurepassword') as z:
            self.assertEqual(self.test_str, z.files[0].peek())

        self.assertRaises(WrongPassword, lambda: ZipFile.open('ZipEncrypted.zip', 'wrongpassword'))

    def test_exctract(self):  # This test should finish without exceptions (os exceptions mainly)
        with ZipFile.open('folders.zip') as z:
            z.extract_all()

    def test_add_folder(self):
        z = ZipFile.new()
        z.add_folder('.\\test1\\test2')
        self.assertEqual(['test1/', 'test1/test2/'], list(z.files['.'].keys()))

    def test_new(self):
        zipfile = ZipFile.new()
        time = datetime.datetime.now()
        zipfile.add_file(
            'lorem ipsum.txt',
            self.test_str,
            compression=DEFLATE,
            level=MAXIMUM,
            last_mod_time=time,
            comment='LOREM'
        )
        zipfile.add_file(
            'lorem ipsum.txt',
            '.\\lorem.txt',
            compression=DEFLATE64,
            level=MAXIMUM,
            last_mod_time=time,
            comment='LOREM2'
        )
        zipfile.save('new.zip', comment='Lorem')

        with ZipFile.open('new.zip') as z:
            self.assertEqual(self.test_str, z.files[0].peek())
            self.assertEqual('Lorem', z.comment)
            self.assertEqual('LOREM2', z.files[0].comment)

        zipfile = ZipFile.new()
        zipfile.add_file('test.txt', 'TEXT', '.\\test1\\test2')
        self.assertEqual(['test1/', 'test1/test2/', 'test1/test2/test.txt'], list(zipfile.files['.'].keys()))

if __name__ == '__main__':
    unittest.main()
