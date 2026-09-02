import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { gitConfig } from './shared';
import { withBase } from './seo';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <>
          {/* the shield's inner "8" is white in one variant and near-black in
              the other, so the mark must follow the theme */}
          <img src={withBase("/assets/mark-light.png")} alt="" width={20} height={20}
               className="shrink-0 dark:hidden" />
          <img src={withBase("/assets/mark-dark.png")} alt="" width={20} height={20}
               className="hidden shrink-0 dark:block" />
          <span className="font-medium">
            Infiltr8: <span className="text-fd-primary">Red-Book</span>
          </span>
        </>
      ),
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
  };
}
