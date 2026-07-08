#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define START_BALANCE 1836

struct item {
    const char *name;
    int price;
    int is_flag;
};

static struct item catalog[] = {
    { "Sticker",       18,      0 },
    { "Coffee Mug",    36,     0 },
    { "Hoodie",        1836,     0 },
    { "The Flag",      36363636, 1 },
};
static const int N_ITEMS = (int)(sizeof(catalog) / sizeof(catalog[0]));

static int balance = START_BALANCE;

static void print_flag(void)
{
    FILE *f = fopen("flag.txt", "r");
    if (!f) {
        puts("LYKNCTF{wr4p_wr4p_wr4p}");
        return;
    }
    char buf[256];
    if (fgets(buf, sizeof(buf), f))
        fputs(buf, stdout);
    size_t n = strlen(buf);
    if (n == 0 || buf[n - 1] != '\n')
        putchar('\n');
    fclose(f);
}

static void show_catalog(void)
{
    puts("\n=== CATALOG ===");
    for (int i = 0; i < N_ITEMS; i++)
        printf("  [%d] %-12s %d coin%s\n",
               i, catalog[i].name, catalog[i].price,
               catalog[i].is_flag ? "  (the good stuff)" : "");
    printf("Balance: %d coin\n", balance);
}

static void buy(void)
{
    int idx, qty;

    printf("Item index: ");
    if (scanf("%d", &idx) != 1) { puts("bad input"); exit(1); }
    if (idx < 0 || idx >= N_ITEMS) { puts("No such item."); return; }

    printf("Quantity: ");
    if (scanf("%d", &qty) != 1) { puts("bad input"); exit(1); }

    int total = catalog[idx].price * qty;

    printf("Total cost: %d coin\n", total);

    if (total > balance) {
        puts("Not enough coins. Come back when you're richer.");
        return;
    }

    balance -= total;
    printf("Purchased %d x %s. New balance: %d coin\n",
           qty, catalog[idx].name, balance);

    if (catalog[idx].is_flag && qty >= 1) {
        puts("\nHere is your flag:");
        print_flag();
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("Welcome to the Integer Overflow Shop!");
    puts("You have 100 coins. The flag is... a little out of budget.");

    for (;;) {
        show_catalog();
        printf("\n[c]atalog  [b]uy  [q]uit > ");
        int c = getchar();
        while (c == '\n' || c == ' ' || c == '\t' || c == '\r')
            c = getchar();

        if (c == EOF || c == 'q') {
            puts("Bye.");
            break;
        } else if (c == 'c') {
            continue;
        } else if (c == 'b') {
            buy();
        } else {
            puts("Unknown command.");
        }
    }
    return 0;
}
