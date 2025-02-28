CC = gcc
CFLAGS = -Wall -Wextra -w -O2 -I./radiotap  # Указываем путь для заголовочных файлов
LDFLAGS = -lpcap
OBJ = wifimon.o radiotap/radiotap.o  # Указываем путь для исходников
TARGET = wifimon

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

# Компиляция объектов из radiotap/ с учетом пути
radiotap/radiotap.o: radiotap/radiotap.c
	$(CC) $(CFLAGS) -c radiotap/radiotap.c -o radiotap/radiotap.o

wifimon.o: wifimon.c
	$(CC) $(CFLAGS) -c wifimon.c -o wifimon.o

clean:
	rm -f $(OBJ) $(TARGET)
