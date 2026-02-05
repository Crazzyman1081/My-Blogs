import { getAllPostIds, getPostData, PostData } from "@/lib/posts";
import styles from './post.module.css';
import TableOfContents from "@/components/TableOfContents";

interface PageProps {
    params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
    const paths = getAllPostIds();
    return paths.map((path) => ({
        slug: path.params.slug,
    }));
}

export default async function Post({ params }: PageProps) {
    const { slug } = await params;
    const postData: PostData = await getPostData(slug);
    const headings = postData.headings || [];

    return (
        <article className={styles.layout}>
            <div className={styles.mainContent}>
                <div className={styles.header}>
                    <h1 className={styles.title}>{postData.title}</h1>
                    <div className={styles.date}>{postData.date}</div>
                </div>

                <div
                    className={styles.content}
                    dangerouslySetInnerHTML={{ __html: postData.contentHtml || '' }}
                />
            </div>

            <aside className={styles.sidebar}>
                <TableOfContents headings={headings} />
            </aside>
        </article>
    );
}
