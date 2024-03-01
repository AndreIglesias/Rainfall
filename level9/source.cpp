#include <cstring>
#include <cstdlib>

class N {
public:
    char buffer[100];
    int value;

    N(int value) : value(value) {}

    void setAnnotation(char* annotation) {
        int len = strlen(annotation);

        std::memcpy(this->buffer, annotation, len);
    }

    int operator+(const N &right) const {
        return (this->value + right.value);
    }

    int operator-(const N &right) const {
        return (this->value - right.value);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        exit(1);
    }

    N* instance1 = new N(5);
    N* instance2 = new N(6);

    instance1->setAnnotation(argv[1]);

    return (*instance2 + *instance1);
}
