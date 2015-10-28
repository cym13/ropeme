NAME    := ropeme
CC_OPTS := -m32 -o $(NAME)

all: $(NAME)

ropeme: $(NAME).c.b64
	base64 -d $(NAME).c.b64 | gcc $(CC_OPTS) -x c -

clean:
	rm $(NAME)
