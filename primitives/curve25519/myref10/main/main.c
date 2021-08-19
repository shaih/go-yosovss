#include <stdio.h>
#include <assert.h>
#include <time.h>

#include <sodium.h>
#include <myref10.h>

#include "private/ed25519_ref10.h"

void
ge25519_p3_dbl(ge25519_p1p1 *r, const ge25519_p3 *p);
void
ge25519_p2_dbl(ge25519_p1p1 *r, const ge25519_p2 *p);
void
ge25519_madd(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q);

void test_crypto_multi_scalarmult_ed25519_vartime_xy();

void generateBaseH();

void smallBenchmark();

int main() {
    if (sodium_init() < 0) {
        printf("ERROR: sodium cannot be initialized\n");
        return -1;
    }

    // generateBaseH();
    test_crypto_multi_scalarmult_ed25519_vartime_xy();
    // smallBenchmark();

    return 0;
}

void test_crypto_multi_scalarmult_ed25519_vartime_xy() {
    unsigned char base_h[64] = {0x00, 0x88, 0x1a, 0xda, 0x54, 0x70, 0x0f, 0x83, 0x04, 0xf3, 0xbb, 0xd1, 0x1a, 0x88, 0xb6, 0xda, 0x29, 0x98, 0x4c, 0x59, 0x49, 0x6e, 0xb3, 0x03, 0xd4, 0xd3, 0x72, 0xc2, 0x8d, 0xd6, 0x09, 0x63, 0xdd, 0x9e, 0x4f, 0x62, 0x21, 0xd1, 0xde, 0xcb, 0x4f, 0x1e, 0x7e, 0x2c, 0x6e, 0xc8, 0xc4, 0x96, 0xe6, 0x64, 0x58, 0x32, 0xdb, 0xf6, 0x61, 0x87, 0x2c, 0xc7, 0xbb, 0xf4, 0x60, 0xf5, 0x4a, 0x16};
    unsigned char s[32];
    unsigned char res1[64], res2[64];

    printf("\n\ntest_crypto_multi_scalarmult_ed25519_vartime_xy\n");

    // crypto_core_ed25519_scalar_random(s);
    sodium_memzero(s, 32);
    s[0] = 100;

    crypto_multi_scalarmult_ed25519_vartime_xy(res1, s, base_h, 1);
    crypto_scalarmult_ed25519_base_h_xy(res2, s);

    if (memcmp(res1, res2, 64)) {
        printf("ERROR!\n");
    } else {
        printf("OK\n");
    }

    printf("\n\n");

}

// from https://stackoverflow.com/a/36095407
static long getNanos() {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (long) ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static void printBenchmark(char *name, long last_time, long new_time, long rep) {
    printf("%-30s %12ld ns/op (%6ld repetitions)\n",
           name,
           (new_time - last_time) / rep,
           rep
    );
}

void smallBenchmark() {
#define NB_POINTS 256
    printf("WARNING: BE SURE TO BE IN RELEASE MODE!!\n");
    printf("Benchmark\n");
    printf("Parameters:\n");
    printf("  number of points added: %d\n", NB_POINTS);
    printf("\n");

    unsigned char points[NB_POINTS][32];
    for (int i = 0; i < NB_POINTS; i++) {
        crypto_core_ed25519_random(points[i]);
    }


    long last_time, new_time, rep;

    //
    // Benchmark ge25519_frombytes
    //
    {
        ge25519_p3 p1_p3;

        last_time = getNanos();

        rep = 1000;
        for (int k = 0; k < rep; k++) {
            if (ge25519_frombytes(&p1_p3, points[0]) != 0) {
                printf("ERROR in ge25519_frombytes line: %d", __LINE__);
            }
        }

        new_time = getNanos();
        printBenchmark("ge25519_frombytes", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_tobytes
    //
    {
        unsigned char r[32];
        ge25519_p3 p1_p3;

        if (ge25519_frombytes(&p1_p3, points[0]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }

        last_time = getNanos();

        rep = 1000;
        for (int k = 0; k < rep; k++) {
            ge25519_p3_tobytes(r, &p1_p3);
        }

        new_time = getNanos();
        printBenchmark("ge25519_tobytes", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_is_on_curve
    //
    {
        ge25519_p3 p1_p3;

        if (ge25519_frombytes(&p1_p3, points[0]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }

        last_time = getNanos();

        rep = 10000;
        for (int k = 0; k < rep; k++) {
            if (ge25519_is_on_curve(&p1_p3)!= 1) {
                printf("ERROR in ge25519_is_on_curve line: %d", __LINE__);
            }
        }

        new_time = getNanos();
        printBenchmark("ge25519_is_on_curve", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_xy_is_on_curve
    //
    {
        ge25519_p3 p1_p3;
        ge25519_xy p1_xy;

        if (ge25519_frombytes(&p1_p3, points[0]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }
        ge25519_p3_to_xy(&p1_xy, &p1_p3);

        last_time = getNanos();

        rep = 10000;
        for (int k = 0; k < rep; k++) {
            if (ge25519_xy_is_on_curve(&p1_xy)!= 1) {
                printf("ERROR in ge25519_xy_is_on_curve line: %d", __LINE__);
            }
        }

        new_time = getNanos();
        printBenchmark("ge25519_xy_is_on_curve", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_p3_to_cached
    //
    {
        ge25519_cached p1_cached;
        ge25519_p3 p1_p3;

        if (ge25519_frombytes(&p1_p3, points[0]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }

        last_time = getNanos();

        rep = 100000;
        for (int k = 0; k < rep; k++) {
            ge25519_p3_to_cached(&p1_cached, &p1_p3);
        }

        new_time = getNanos();
        printBenchmark("ge25519_p3_to_cached", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_add
    //
    {
        ge25519_cached p2_cached;
        ge25519_p3 p1_p3, p2_p3;
        ge25519_p1p1 p1_p1p1;

        if (ge25519_frombytes(&p1_p3, points[0]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }
        if (ge25519_frombytes(&p2_p3, points[1]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }
        ge25519_p3_to_cached(&p2_cached, &p2_p3);

        last_time = getNanos();

        rep = 1000000;
        for (int k = 0; k < rep; k++) {
            ge25519_add(&p1_p1p1, &p1_p3, &p2_cached);
        }

        new_time = getNanos();
        printBenchmark("ge25519_add", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_madd
    //
    {
        ge25519_precomp p2_precomp;
        ge25519_p3 p1_p3, p2_p3;
        ge25519_p1p1 p1_p1p1;
        ge25519_xy p2_xy;

        if (ge25519_frombytes(&p1_p3, points[0]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }
        if (ge25519_frombytes(&p2_p3, points[1]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }
        ge25519_p3_to_xy(&p2_xy, &p2_p3);
        ge25519_xy_to_precomp(&p2_precomp, &p2_xy);

        last_time = getNanos();

        rep = 1000000;
        for (int k = 0; k < rep; k++) {
            ge25519_madd(&p1_p1p1, &p1_p3, &p2_precomp);
        }

        new_time = getNanos();
        printBenchmark("ge25519_madd", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_p3_dbl
    //
    {
        ge25519_cached p2_cached;
        ge25519_p3 p1_p3, p2_p3;
        ge25519_p1p1 p1_p1p1;

        if (ge25519_frombytes(&p1_p3, points[0]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }
        if (ge25519_frombytes(&p2_p3, points[1]) != 0) {
            printf("ERROR in ge25519_frombytes line: %d", __LINE__);
        }
        ge25519_p3_to_cached(&p2_cached, &p2_p3);

        last_time = getNanos();

        rep = 1000000;
        for (int k = 0; k < rep; k++) {
            ge25519_p3_dbl(&p1_p1p1, &p1_p3);
        }

        new_time = getNanos();
        printBenchmark("ge25519_p3_dbl", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_p2_dbl
    //
    {
        ge25519_cached p2_cached;
        ge25519_p3 p1_p3, p2_p3;
        ge25519_p1p1 p1_p1p1;
        ge25519_p2 p1_p2;

        ge25519_frombytes(&p1_p3, points[0]);
        ge25519_frombytes(&p2_p3, points[1]);
        ge25519_p3_to_cached(&p2_cached, &p2_p3);
        ge25519_add(&p1_p1p1, &p1_p3, &p2_cached);
        ge25519_p1p1_to_p2(&p1_p2, &p1_p1p1);

        last_time = getNanos();

        rep = 1000000;
        for (int k = 0; k < rep; k++) {
            ge25519_p2_dbl(&p1_p1p1, &p1_p2);
        }

        new_time = getNanos();
        printBenchmark("ge25519_p2_dbl", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_p1p1_to_p3
    //
    {
        ge25519_cached p2_cached;
        ge25519_p3 p1_p3, p2_p3;
        ge25519_p1p1 p1_p1p1;

        ge25519_frombytes(&p1_p3, points[0]);
        ge25519_frombytes(&p2_p3, points[1]);
        ge25519_p3_to_cached(&p2_cached, &p2_p3);
        ge25519_add(&p1_p1p1, &p1_p3, &p2_cached);

        last_time = getNanos();

        rep = 1000000;
        for (int k = 0; k < rep; k++) {
            ge25519_p1p1_to_p3(&p1_p3, &p1_p1p1);
        }

        new_time = getNanos();
        printBenchmark("ge25519_p1p1_to_p3", last_time, new_time, rep);
    }

    //
    // Benchmark ge25519_p1p1_to_p2
    //
    {
        ge25519_cached p2_cached;
        ge25519_p3 p1_p3, p2_p3;
        ge25519_p1p1 p1_p1p1;
        ge25519_p2 p1_p2;

        ge25519_frombytes(&p1_p3, points[0]);
        ge25519_frombytes(&p2_p3, points[1]);
        ge25519_p3_to_cached(&p2_cached, &p2_p3);
        ge25519_add(&p1_p1p1, &p1_p3, &p2_cached);

        last_time = getNanos();

        rep = 1000000;
        for (int k = 0; k < rep; k++) {
            ge25519_p1p1_to_p2(&p1_p2, &p1_p1p1);
        }

        new_time = getNanos();
        printBenchmark("ge25519_p1p1_to_p2", last_time, new_time, rep);
    }

    //
    // Benchmark crypto_ed25519_add_points
    //
    {
        unsigned char r[32];

        last_time = getNanos();

        rep = 100;
        for (int k = 0; k < rep; k++) {
            crypto_ed25519_add_points(r, points[0], NB_POINTS);
        }

        new_time = getNanos();
        printBenchmark("crypto_ed25519_add_points", last_time, new_time, rep);
    }

    //
    // Benchmark add points directly in p3 representation
    //
    {
        ge25519_p3 points_p3[NB_POINTS];

        // convert to p3 beforehand
        for (int i = 0; i < NB_POINTS; i++) {
            ge25519_frombytes(&points_p3[i], points[0]);
        }

        ge25519_p3 r_p3;
        ge25519_p1p1 r_p1p1;
        ge25519_cached q_cached;

        last_time = getNanos();

        rep = 1000;
        for (int k = 0; k < rep; k++) {
            fe25519_copy(r_p3.X, points_p3[0].X);
            fe25519_copy(r_p3.Y, points_p3[0].Y);
            fe25519_copy(r_p3.Z, points_p3[0].Z);
            fe25519_copy(r_p3.T, points_p3[0].T);

            for (int i = 1; i < NB_POINTS; i++) {
                ge25519_p3_to_cached(&q_cached, &points_p3[i]);
                ge25519_add(&r_p1p1, &r_p3, &q_cached);
                ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
            }
        }

        new_time = getNanos();
        printBenchmark("add points directly from p3", last_time, new_time, rep);
    }


}

void generateBaseH() {
    printf("Generating the point H for Pedersen:\n");

    // It is the hash of an arbitrary message then converted to a point
    assert(crypto_generichash_BYTES == 32);
    assert(crypto_core_ed25519_UNIFORMBYTES == 32);
    unsigned char MESSAGE[] = "YOSO Pedersen H...";
    // we chose a string until we got a high-bit of the point equal to 0
// looks like otherwise we have weird issues...
// my guess is that the Python script only supports high-bit = 0, as high-bit encodes the X coord
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof hash,
                       MESSAGE, sizeof MESSAGE,
                       NULL, 0);

    unsigned char hx[crypto_core_ed25519_BYTES];
    crypto_core_ed25519_from_uniform(hx, hash);


    unsigned char hx_big_endian[crypto_core_ed25519_BYTES];
    for (int i = 0; i < crypto_core_ed25519_BYTES; i++) {
        hx_big_endian[i] = hx[crypto_core_ed25519_BYTES - i - 1];
    }

    char hx_hex[2 * crypto_core_ed25519_BYTES + 1];
    sodium_bin2hex(hx_hex, sizeof hx_hex, hx_big_endian, sizeof hx_big_endian);

    printf("%s", hx_hex);
}
