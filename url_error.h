#ifndef _URL_ERROR_H_
#define _URL_ERROR_H_

/** Код ошибки, означающий, что в процессе работы функции возникли проблемы
 * с динамическим выделением памяти.
 * */
#define ERROR_MEMORY_ALLOC -5

/** Код ошибки, означающий, что переданный функции буфер слишком мал
 * для помещения в него результата её работы.
 *  */
#define ERROR_BUFFER_OVERFLOW -10

/** Код ошибки, означающий, что переданный функции номер порта является некорректным.
 *  */
#define ERROR_INCORRECT_PORT -11

/** Код ошибки, означающий, что в данном query нет параметра с таким именем.
 *  */
#define ERROR_NO_SUCH_KEY -12

/** Код ошибки, означающий, что в данном query параметр с таким именем уже существует.
 *  */
#define ERROR_KEY_ALREADY_EXIST -13

/** Код ошибки, означающий, что в данном query параметра с таким индексом нет.
 *  */
#define ERROR_NO_SUCH_KEY_INDEX -14

/** Код ошибки, означающий, что функции не удалось обработать имя хоста в соотсетствии с требованиями IDNA.
 *  */
#define ERROR_INCORRECT_HOST_NAME -15

/** Код ошибки, означающий, что не удалось выполнить подстановку символов для IDNA.
 *  */
#define ERROR_IDNA_SUBSTITITE -17

/** Код ошибки, означающий, что функции iconv()не удалось
 * выполнить требуеиое преобразование кодировки.
 *  */
#define ERROR_INCORRECT_MULTIBYTE_SEQUENCE -18

/** Код ошибки, означающий, что не удалось установить связь или
 * открыть файл базы данных url2cat.
 *  */
#define ERROR_URL_DATABASE_CONNECT -19

/** Код ошибки, означающий, что не удалось корректно инициализировать базу данных url2cat.
 *  */
#define ERROR_URL_DATABASE_INITIALIZE -20

/** Код ошибки, означающий, что данного URL нет в базе данных url2cat.
 *  */
#define ERROR_URL_NOT_IN_DATABASE -21

/** Код ошибки, означающий, что данный URL уже есть в базе данных url2cat.
 *  */
#define ERROR_URL_IN_DATABASE -22

/** Код ошибки, означающий, что произошла ошибка при работе с базой данных url2cat.
 *  */
#define ERROR_DATABASE_OPERATION -23

/** Код ошибки, означающий, что строка, содержащая информацию об обновлении базы данных url2cat,
 *  имеет неверный формат.
 *  */
#define ERROR_UPDATE_STRING_FORMAT -24

/** Код ошибки, означающий, что не удалось открыть файл с метаинформацией об опорной базе данных.
 *  */
#define ERROR_OPEN_META_FILE -25

/** Код ошибки, означающий, что не удалось прочитать информацию из файла
 * с метаинформацией об опорной базе данных.
 *  */
#define ERROR_READ_META_FILE -26

/** Код ошибки, означающий, что при чтении метаинформации об опорной базе данных
 * длина ключа или значения оказалась больше предельно допустимой.
 *  */
#define ERROR_READ_META_FILE_OVERFLOW -27

/** Код ошибки, означающий, что в данной метаинформации об опорной базе данных
 * нет нужного ключа.
 *  */
#define ERROR_META_NO_SUCH_KEY -28

/** Код ошибки, означающий, что в данной метаинформации об опорной базе данных
 * уже есть заданный ключ.
 *  */
#define ERROR_META_KEY_EXISTS -29

/** Код ошибки, означающий, что в данная метаинформация об опорной базе данных не инициализирована.
 *  */
#define ERROR_META_NOT_INITIALIZED -30

/** Код ошибки, означающий, что невозможно открыть указанный patch-файл, содержащий инкрементные
 * обновления опорной базы данных.
 *  */
#define ERROR_PATCH_OPEN -31

/** Код ошибки, означающий, что не удалось прочитать из patch-файла информацию об инкрементальном обновлении.
 *  */
#define ERROR_PATCH_READ -32

/** Код ошибки, означающий, что невозмжно обновить метаинформацию при инкрементальном обновлении,
 * так как опорная база данных её не имеет.
 *  */
#define ERROR_PATCH_META_EMPTY -33

/** Код ошибки, означающий, что есть ошибка в формате метаданных в patch-файле.
 *  */
#define ERROR_PATCH_META_FORMAT -34

/** Код ошибки, означающий, что произошла ошибка инкрементального обновления метаданных
 * опорной БД.
 *  */
#define ERROR_PATCH_META -35

/** Код ошибки, означающий, что есть в patch-файле первая строка не является корректной строкой контрольной суммы.
 *  */
#define ERROR_PATCH_CHECKSUM_FORMAT -36

/** Код ошибки, означающий, что есть в произошла ошибка при вычислении контрольной суммы patch-файла.
 *  */
#define ERROR_PATCH_CHECKSUM_CALC -37

/** Код ошибки, означающий, что есть в произошла ошибка при проверке контрольной суммы patch-файла.
 *  */
#define ERROR_PATCH_CHECKSUM -38

/** Код ошибки, означающий, что patch-файл не подходит для данной версии БД.
 *  */
#define ERROR_PATCH_DBVERSION -39


#endif /* _URL_ERROR_H_ */