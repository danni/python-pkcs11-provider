CYTHON = cython

CFLAGS = \
	-fPIC \
	-Wall \
	-Wextra \
	$(shell pkg-config --cflags python3) \
	-D "CK_PTR=*" \
	-D "CK_DEFINE_FUNCTION(returnType, name)=returnType name" \
	-D "CK_DECLARE_FUNCTION(returnType, name)=returnType name" \
	-D "CK_DECLARE_FUNCTION_POINTER(returnType, name)=returnType (* name)" \
	-D "CK_CALLBACK_FUNCTION(returnType, name)=returnType (* name)" \
	$(NULL)

LDFLAGS = \
	-shared \
	$(shell pkg-config --libs python3) \
	$(NULL)

SRC = \
	src/pkcs11.pyx

TARGET = python-pkcs11-provider.so

%.c: %.pyx
	$(CYTHON) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

OBJS = $(SRC:.pyx=.o)
OBJS += src/entrypoint.o

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
