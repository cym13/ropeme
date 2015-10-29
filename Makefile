NAME    := ropeme
CC_OPTS := -m32 -o $(NAME)

all: $(NAME)

ropeme: $(NAME).c.b64
	base64 -d $(NAME).c.b64 | gcc $(CC_OPTS) -x c -

edit:
	base64 -d $(NAME).c.b64 > $(NAME).c
	$(EDITOR) $(NAME).c
	base64 $(NAME).c > $(NAME).c.b64
	rm $(NAME).c

clean:
	rm $(NAME)
